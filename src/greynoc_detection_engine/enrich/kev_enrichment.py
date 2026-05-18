from __future__ import annotations

from greynoc_detection_engine.models.kev import KEVRecord


class KEVEnricher:
    def priority_tags(self, kev: KEVRecord) -> list[str]:
        tags = ["known-exploited"]
        if kev.known_ransomware_campaign_use == "Known":
            tags.append("known-ransomware-use")
        if "disconnect" in kev.required_action.lower():
            tags.append("urgent-mitigation")
        return tags
