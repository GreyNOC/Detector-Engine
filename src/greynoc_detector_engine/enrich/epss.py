from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from typing import Any

from greynoc_detector_engine.models.prediction import EPSSScore
from greynoc_detector_engine.utils.time import parse_datetime, utc_now


class EPSSEnricher:
    """Attach FIRST.org EPSS scores to CVEs.

    EPSS expresses the probability a CVE is exploited in the next 30 days. We
    treat it as an authoritative, *external* predictive prior that complements
    our own forecast: when EPSS is high but our internal signals are quiet,
    the model widens its confidence band rather than overriding EPSS.
    """

    def __init__(self, scores_by_cve: dict[str, EPSSScore] | None = None) -> None:
        self._scores: dict[str, EPSSScore] = {}
        if scores_by_cve:
            self._scores.update(scores_by_cve)

    def load(self, scores: Iterable[EPSSScore]) -> None:
        for score in scores:
            self._scores[score.cve_id.upper()] = score

    def for_cve(self, cve_id: str) -> EPSSScore | None:
        return self._scores.get(cve_id.upper())

    def for_cves(self, cve_ids: Iterable[str]) -> list[EPSSScore]:
        return [score for cid in cve_ids if (score := self.for_cve(cid)) is not None]

    @staticmethod
    def from_first_org_payload(payload: Any) -> list[EPSSScore]:
        """Parse the canonical EPSS API JSON envelope into model instances."""

        rows: list[dict[str, Any]] = []
        if isinstance(payload, dict) and isinstance(payload.get("data"), list):
            rows = [item for item in payload["data"] if isinstance(item, dict)]
        elif isinstance(payload, list):
            rows = [item for item in payload if isinstance(item, dict)]

        scores: list[EPSSScore] = []
        for row in rows:
            cve_id = row.get("cve") or row.get("cve_id")
            if not cve_id:
                continue
            try:
                epss = float(row.get("epss", 0.0))
                percentile = float(row.get("percentile", 0.0))
            except (TypeError, ValueError):
                continue
            score_date_raw = row.get("date") or row.get("score_date")
            score_date: datetime = parse_datetime(score_date_raw) or utc_now()
            scores.append(
                EPSSScore(
                    cve_id=str(cve_id).upper(),
                    epss=max(0.0, min(1.0, epss)),
                    percentile=max(0.0, min(1.0, percentile)),
                    score_date=score_date,
                )
            )
        return scores
