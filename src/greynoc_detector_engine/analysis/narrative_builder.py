from __future__ import annotations

from greynoc_detector_engine.models.threat import ThreatRecord


class NarrativeBuilder:
    def build(self, threat: ThreatRecord) -> str:
        parts = [threat.summary]
        if threat.related_cves:
            parts.append(f"Related CVEs: {', '.join(threat.related_cves)}.")
        if threat.related_kev_entries:
            parts.append("CISA KEV correlation indicates confirmed exploitation pressure.")
        if threat.ai_attack_type:
            parts.append(f"AI attack taxonomy classification: {threat.ai_attack_type.value}.")
        return " ".join(part for part in parts if part)
