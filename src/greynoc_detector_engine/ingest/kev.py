from __future__ import annotations

from typing import Any

from greynoc_detector_engine.ingest.base import BaseIngestor
from greynoc_detector_engine.models.kev import KEVRecord
from greynoc_detector_engine.normalize.normalizer import source_reference_from_record
from greynoc_detector_engine.utils.time import parse_date


class KEVIngestor(BaseIngestor[KEVRecord]):
    def ingest(self) -> list[KEVRecord]:
        payload = self.load_json_payload()
        return [self._normalize_record(item) for item in self._iter_records(payload)]

    @staticmethod
    def _iter_records(payload: Any) -> list[dict[str, Any]]:
        if isinstance(payload, dict) and isinstance(payload.get("vulnerabilities"), list):
            return [item for item in payload["vulnerabilities"] if isinstance(item, dict)]
        if isinstance(payload, dict) and isinstance(payload.get("kev"), list):
            return [item for item in payload["kev"] if isinstance(item, dict)]
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        if isinstance(payload, dict) and "cveID" in payload:
            return [payload]
        return []

    def _normalize_record(self, record: dict[str, Any]) -> KEVRecord:
        cve_id = record.get("cveID") or record.get("cve_id")
        short_description = record.get("shortDescription") or record.get("short_description") or ""
        source_ref = source_reference_from_record(
            title=f"{cve_id} CISA KEV record",
            source=self.source_config.name,
            url=self.source_config.url,
            content=f"{cve_id} {short_description} {record.get('requiredAction', '')}",
        )
        required_action = record.get("requiredAction") or record.get("required_action") or ""
        return KEVRecord(
            cve_id=str(cve_id),
            vendor_project=str(record.get("vendorProject") or record.get("vendor_project") or ""),
            product=str(record.get("product") or ""),
            vulnerability_name=str(
                record.get("vulnerabilityName") or record.get("vulnerability_name") or ""
            ),
            date_added=parse_date(record.get("dateAdded") or record.get("date_added")),
            short_description=str(short_description),
            required_action=str(required_action),
            due_date=parse_date(record.get("dueDate") or record.get("due_date")),
            known_ransomware_campaign_use=record.get("knownRansomwareCampaignUse")
            or record.get("known_ransomware_campaign_use"),
            notes=record.get("notes"),
            source_references=[source_ref],
        )
