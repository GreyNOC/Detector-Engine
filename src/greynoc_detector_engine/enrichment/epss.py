from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from greynoc_detector_engine.config.settings import Settings
from greynoc_detector_engine.models.cve import CVERecord
from greynoc_detector_engine.utils.http import DefensiveHttpClient


class EPSSRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cve_id: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$")
    epss_score: float = Field(ge=0, le=1)
    percentile: float | None = Field(default=None, ge=0, le=1)


class EPSSClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.http = DefensiveHttpClient(
            timeout_seconds=settings.request_timeout_seconds,
            user_agent=settings.user_agent,
            retries=settings.http_retries,
            max_response_bytes=settings.max_response_bytes,
            allowed_hosts=settings.allowed_fetch_hosts,
        )

    def load_records(self, *, fixture_path: Path | None = None) -> list[EPSSRecord]:
        if fixture_path:
            import json

            with fixture_path.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
        else:
            if not self.settings.fetch_live:
                raise RuntimeError("EPSS enrichment requires a fixture or GREYNOC_FETCH_LIVE=true")
            payload = self.http.get_json("https://api.first.org/data/v1/epss")
        return self._parse_payload(payload)

    def _parse_payload(self, payload: Any) -> list[EPSSRecord]:
        if isinstance(payload, dict) and isinstance(payload.get("data"), list):
            rows = payload["data"]
        elif isinstance(payload, dict) and isinstance(payload.get("epss"), list):
            rows = payload["epss"]
        elif isinstance(payload, list):
            rows = payload
        else:
            rows = []

        records: list[EPSSRecord] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            cve_id = row.get("cve") or row.get("cve_id")
            score = row.get("epss") or row.get("epss_score")
            if cve_id is None or score is None:
                continue
            records.append(
                EPSSRecord(
                    cve_id=str(cve_id).upper(),
                    epss_score=float(score),
                    percentile=float(row["percentile"]) if row.get("percentile") is not None else None,
                )
            )
        return records


def enrich_cves_with_epss(cves: list[CVERecord], records: list[EPSSRecord]) -> list[CVERecord]:
    epss_by_cve = {record.cve_id: record for record in records}
    enriched: list[CVERecord] = []
    for cve in cves:
        epss = epss_by_cve.get(cve.cve_id)
        if epss is None:
            enriched.append(cve)
            continue
        tags = sorted(set(cve.tags) | {"epss-enriched"})
        enriched.append(cve.model_copy(update={"epss_score": epss.epss_score, "tags": tags}))
    return enriched
