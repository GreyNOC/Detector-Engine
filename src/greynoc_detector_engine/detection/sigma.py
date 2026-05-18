from __future__ import annotations

import yaml

from greynoc_detector_engine.detection.safety import sanitize_rule_term, sanitize_rule_terms
from greynoc_detector_engine.models.detection import DetectionKind, GeneratedDetection
from greynoc_detector_engine.models.threat import ThreatRecord


class SigmaGenerator:
    def generate(self, threat: ThreatRecord) -> GeneratedDetection:
        terms = sanitize_rule_terms(
            threat.related_cves or threat.affected_products or [threat.title]
        )
        rule = {
            "title": sanitize_rule_term(f"Draft Hunt - {threat.title}") or "Draft Hunt",
            "id": f"{threat.threat_id}-sigma-draft",
            "status": "test",
            "description": sanitize_rule_term(threat.summary) or "",
            "references": [ref.url for ref in threat.source_references if ref.url],
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection": {"CommandLine|contains": terms},
                "condition": "selection",
            },
            "falsepositives": ["Administrative tooling or vulnerability scanner output."],
            "level": threat.severity.value,
        }
        return GeneratedDetection(
            related_threat_id=threat.threat_id,
            kind=DetectionKind.SIGMA,
            title=f"Draft Sigma Hunt for {threat.title}",
            description="Draft Sigma hunt rule based on defensive metadata; validate before use.",
            required_telemetry=["Process creation telemetry with command-line capture."],
            rule_query=yaml.safe_dump(rule, sort_keys=False),
            false_positives=["Legitimate scanners, administrators, or patch-verification tooling."],
            validation_steps=[
                "Replay against known-good administrative activity.",
                "Validate field names against the target SIEM Sigma backend.",
            ],
            assumptions=["Threat metadata contains searchable CVE or product terms."],
            references=threat.source_references,
            confidence=0.35,
        )
