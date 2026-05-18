from __future__ import annotations

from greynoc_detector_engine.detection.safety import sanitize_rule_term, sanitize_rule_terms
from greynoc_detector_engine.models.detection import DetectionKind, GeneratedDetection
from greynoc_detector_engine.models.threat import ThreatRecord


class ElasticGenerator:
    def generate(self, threat: ThreatRecord) -> GeneratedDetection:
        terms = sanitize_rule_terms(
            threat.related_cves or threat.affected_products or [threat.title]
        )
        safe_title = sanitize_rule_term(threat.title) or "draft"
        query = " or ".join(f'"{term}"' for term in terms) or '"unspecified"'
        return GeneratedDetection(
            related_threat_id=threat.threat_id,
            kind=DetectionKind.ELASTIC,
            title=f"Draft Elastic KQL Hunt for {safe_title}",
            description="Draft KQL hunt for related defensive metadata terms.",
            required_telemetry=[
                "Endpoint, web, proxy, application, or vulnerability scanner logs."
            ],
            rule_query=query,
            false_positives=["Benign scanner output, patch notes, and administrator activity."],
            validation_steps=["Constrain data views and fields before operational use."],
            assumptions=["CVE or product terms appear in indexed event fields."],
            references=threat.source_references,
            confidence=0.35,
        )
