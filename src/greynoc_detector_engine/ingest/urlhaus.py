from __future__ import annotations

from typing import Any

from greynoc_detector_engine.enrich.reputation import (
    IndicatorReputation,
    ReputationVerdict,
)
from greynoc_detector_engine.ingest.base import BaseIngestor
from greynoc_detector_engine.models.indicator import IndicatorType


class URLhausIngestor(BaseIngestor[IndicatorReputation]):
    """Pull abuse.ch URLhaus malicious-URL listings into the reputation layer."""

    def ingest(self) -> list[IndicatorReputation]:
        payload = self.load_json_payload()
        rows = self._iter_rows(payload)
        results: list[IndicatorReputation] = []
        for row in rows:
            url = row.get("url") or row.get("malware_url")
            if not url:
                continue
            threat_type = row.get("threat") or row.get("threat_type") or "malware_download"
            tags = [str(t) for t in row.get("tags", []) if isinstance(t, str)]
            reasons = [f"URLhaus tagged {url} as {threat_type}."]
            results.append(
                IndicatorReputation(
                    value=str(url),
                    type=IndicatorType.URL,
                    verdict=ReputationVerdict.MALICIOUS,
                    confidence=0.8,
                    sources=["URLhaus"],
                    tags=sorted({threat_type, *tags}),
                    reasons=reasons,
                )
            )
        return results

    @staticmethod
    def _iter_rows(payload: Any) -> list[dict[str, Any]]:
        if isinstance(payload, dict) and isinstance(payload.get("urls"), list):
            return [r for r in payload["urls"] if isinstance(r, dict)]
        if isinstance(payload, dict) and isinstance(payload.get("data"), list):
            return [r for r in payload["data"] if isinstance(r, dict)]
        if isinstance(payload, list):
            return [r for r in payload if isinstance(r, dict)]
        return []
