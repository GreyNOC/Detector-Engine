from __future__ import annotations

from greynoc_detector_engine.models.detection import DetectionKind, GeneratedDetection
from greynoc_detector_engine.models.threat import ThreatRecord


class SuricataGenerator:
    def generate(self, threat: ThreatRecord) -> GeneratedDetection:
        metadata = "; ".join(
            [
                f"threat_id {threat.threat_id}",
                f"severity {threat.severity.value}",
                "status draft",
            ]
        )
        template = (
            "# Metadata-only Suricata draft. No traffic-matching condition is provided.\n"
            f"# msg: GREYNOC draft network detection for {threat.title}\n"
            f"# metadata: {metadata}\n"
            "# Add protocol, flow, content, and performance constraints only after validation.\n"
        )
        return GeneratedDetection(
            related_threat_id=threat.threat_id,
            kind=DetectionKind.SURICATA,
            title=f"Metadata-only Suricata Template for {threat.title}",
            description="Suricata metadata template; not a deployable network signature.",
            required_telemetry=["Validated packet captures or network telemetry."],
            rule_query=template,
            false_positives=[
                "Not applicable until a traffic-matching rule is authored and validated."
            ],
            validation_steps=["Validate candidate content against benign and attack-replay PCAPs."],
            assumptions=["No validated network indicator is available yet."],
            references=threat.source_references,
            confidence=0.2,
        )
