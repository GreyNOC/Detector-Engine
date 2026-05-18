from __future__ import annotations

from greynoc_detection_engine.enrich.references import add_reference_context
from greynoc_detection_engine.models.cve import CVERecord
from greynoc_detection_engine.models.kev import KEVRecord


class CVEEnricher:
    def enrich(self, cve: CVERecord, kev: KEVRecord | None = None) -> CVERecord:
        enriched = add_reference_context(cve)
        tags = set(enriched.tags)
        if kev:
            tags.add("cisa-kev")
            if kev.known_ransomware_campaign_use == "Known":
                tags.add("known-ransomware-use")
        enriched.tags = sorted(tags)
        return enriched
