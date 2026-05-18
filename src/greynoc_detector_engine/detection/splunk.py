from __future__ import annotations

from greynoc_detector_engine.models.detection import DetectionKind, GeneratedDetection
from greynoc_detector_engine.models.threat import ThreatRecord


class SplunkGenerator:
    def generate(self, threat: ThreatRecord) -> GeneratedDetection:
        terms = threat.related_cves or threat.affected_products or [threat.title]
        escaped_terms = " OR ".join(f'"{term}"' for term in terms)
        query = (
            f"index=* ({escaped_terms}) "
            "| stats count min(_time) as first_seen max(_time) as last_seen by sourcetype host "
            "| where count > 0"
        )
        return GeneratedDetection(
            related_threat_id=threat.threat_id,
            kind=DetectionKind.SPLUNK,
            title=f"Draft Splunk Hunt for {threat.title}",
            description="Draft SPL hunt for references to related CVEs or products in telemetry.",
            required_telemetry=[
                "Endpoint, web, proxy, vulnerability scanner, or application logs."
            ],
            rule_query=query,
            false_positives=[
                "Patch tools, vulnerability scanners, admin scripts, or documentation paths."
            ],
            validation_steps=[
                "Scope indexes and sourcetypes, then compare results against "
                "known maintenance windows."
            ],
            assumptions=["Relevant telemetry stores CVE or product terms as searchable text."],
            references=threat.source_references,
            confidence=0.35,
        )
