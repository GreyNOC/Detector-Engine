from __future__ import annotations

from greynoc_detector_engine.models.detection import DetectionKind, GeneratedDetection
from greynoc_detector_engine.models.threat import ThreatRecord


class YaraGenerator:
    def generate(self, threat: ThreatRecord) -> GeneratedDetection:
        rule_name = threat.threat_id.replace("-", "_")
        references = ", ".join(ref.url or ref.title for ref in threat.source_references[:5])
        rule = f"""rule GREYNOC_Metadata_{rule_name}
{{
    meta:
        description = "Metadata-only draft for {threat.title}"
        threat_id = "{threat.threat_id}"
        severity = "{threat.severity.value}"
        references = "{references}"
        validation = "Add validated strings or structural features before deployment."
    condition:
        false
}}
"""
        return GeneratedDetection(
            related_threat_id=threat.threat_id,
            kind=DetectionKind.YARA,
            title=f"Metadata-only YARA Template for {threat.title}",
            description=(
                "Metadata-only YARA template. Condition is false until validated indicators exist."
            ),
            required_telemetry=[
                "Validated file samples or file telemetry are required before activation."
            ],
            rule_query=rule,
            false_positives=["None while condition is false; future strings require validation."],
            validation_steps=["Add validated benign and malicious test samples before enabling."],
            assumptions=[
                "No malware samples or validated byte patterns are available in this framework."
            ],
            references=threat.source_references,
            confidence=0.2,
        )
