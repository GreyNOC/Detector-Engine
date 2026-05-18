from __future__ import annotations

from greynoc_detection_engine.catalog.deduplication import (
    merge_threats,
    threat_deduplication_key,
)
from greynoc_detection_engine.catalog.storage import StorageBackend
from greynoc_detection_engine.models.threat import ThreatRecord


class ThreatLibrary:
    def __init__(self, storage: StorageBackend) -> None:
        self.storage = storage

    def initialize(self) -> None:
        self.storage.initialize()

    def upsert(self, threat: ThreatRecord) -> ThreatRecord:
        existing_by_id = self.storage.get_threat(threat.threat_id)
        if existing_by_id:
            merged = merge_threats(existing_by_id, threat)
            self.storage.upsert_threat(merged)
            return merged

        incoming_key = threat_deduplication_key(threat)
        for existing in self.storage.list_threats():
            if threat_deduplication_key(existing) == incoming_key:
                merged = merge_threats(existing, threat)
                self.storage.upsert_threat(merged)
                return merged

        self.storage.upsert_threat(threat)
        return threat

    def list_threats(self) -> list[ThreatRecord]:
        return self.storage.list_threats()

    def get(self, threat_id: str) -> ThreatRecord | None:
        return self.storage.get_threat(threat_id)

    def search(self, query: str) -> list[ThreatRecord]:
        needle = query.lower()
        return [
            threat
            for threat in self.storage.list_threats()
            if needle in threat.title.lower()
            or needle in threat.summary.lower()
            or any(needle in product.lower() for product in threat.affected_products)
            or any(needle == cve.lower() for cve in threat.related_cves)
        ]
