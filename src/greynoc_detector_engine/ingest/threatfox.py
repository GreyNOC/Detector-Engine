from __future__ import annotations

from typing import Any

from greynoc_detector_engine.enrich.reputation import (
    IndicatorReputation,
    ReputationVerdict,
)
from greynoc_detector_engine.ingest.base import BaseIngestor
from greynoc_detector_engine.models.indicator import IndicatorType
from greynoc_detector_engine.utils.time import parse_datetime, utc_now

_TYPE_MAP: dict[str, IndicatorType] = {
    "ip:port": IndicatorType.IPV4,
    "ip": IndicatorType.IPV4,
    "domain": IndicatorType.DOMAIN,
    "url": IndicatorType.URL,
    "md5_hash": IndicatorType.FILE_HASH,
    "sha1_hash": IndicatorType.FILE_HASH,
    "sha256_hash": IndicatorType.FILE_HASH,
}


class ThreatFoxIngestor(BaseIngestor[IndicatorReputation]):
    """Pull abuse.ch ThreatFox IOCs into our reputation layer.

    ThreatFox publishes a daily recent-IOC JSON. We accept either the API
    envelope (`{"data": [...]}`) or a fixture list and convert each entry into
    an `IndicatorReputation` row tagged with malware family.
    """

    def ingest(self) -> list[IndicatorReputation]:
        payload = self.load_json_payload()
        rows = self._iter_rows(payload)
        results: list[IndicatorReputation] = []
        for row in rows:
            rep = self._normalize(row)
            if rep is not None:
                results.append(rep)
        return results

    @staticmethod
    def _iter_rows(payload: Any) -> list[dict[str, Any]]:
        if isinstance(payload, dict) and isinstance(payload.get("data"), list):
            return [r for r in payload["data"] if isinstance(r, dict)]
        if isinstance(payload, list):
            return [r for r in payload if isinstance(r, dict)]
        return []

    @staticmethod
    def _normalize(row: dict[str, Any]) -> IndicatorReputation | None:
        ioc_value = row.get("ioc") or row.get("indicator")
        ioc_type_raw = (row.get("ioc_type") or row.get("type") or "").lower()
        if not ioc_value or ioc_type_raw not in _TYPE_MAP:
            return None
        ioc_type = _TYPE_MAP[ioc_type_raw]
        malware = row.get("malware") or row.get("malware_printable")
        threat_type = row.get("threat_type") or row.get("threat_type_desc")
        first_seen = parse_datetime(row.get("first_seen") or row.get("first_seen_utc")) or utc_now()
        tags = [t for t in [malware, threat_type] if isinstance(t, str)]
        label = threat_type or "malicious"
        reasons = [f"ThreatFox listed {ioc_value} as {label} on {first_seen.date()}."]
        return IndicatorReputation(
            value=str(ioc_value),
            type=ioc_type,
            verdict=ReputationVerdict.MALICIOUS,
            confidence=0.85,
            sources=["ThreatFox"],
            tags=sorted({t for t in tags if t}),
            reasons=reasons,
        )
