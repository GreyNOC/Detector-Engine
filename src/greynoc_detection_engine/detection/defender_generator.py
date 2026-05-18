from __future__ import annotations

from greynoc_detection_engine.models.detection import DetectionKind, GeneratedDetection
from greynoc_detection_engine.models.threat import ThreatRecord


class DefenderGenerator:
    def generate(self, threat: ThreatRecord) -> GeneratedDetection:
        terms = threat.related_cves or threat.affected_products or [threat.title]
        kql_terms = ", ".join(f'"{term}"' for term in terms)
        query = f"""let terms = dynamic([{kql_terms}]);
union DeviceEvents, DeviceProcessEvents, DeviceNetworkEvents
| where Timestamp > ago(7d)
| where tostring(AdditionalFields) has_any (terms)
    or ProcessCommandLine has_any (terms)
    or RemoteUrl has_any (terms)
| summarize count(), first_seen=min(Timestamp), last_seen=max(Timestamp) by DeviceName, ActionType
"""
        return GeneratedDetection(
            related_threat_id=threat.threat_id,
            kind=DetectionKind.DEFENDER,
            title=f"Draft Microsoft Defender Hunt for {threat.title}",
            description="Draft Defender Advanced Hunting query for related CVE or product terms.",
            required_logs=[
                "Microsoft Defender for Endpoint device events, process events, and network events."
            ],
            query=query,
            false_positives=["Security tooling, vulnerability scans, and administrative scripts."],
            validation_steps=[
                "Tune terms and event tables against a representative tenant baseline."
            ],
            assumptions=["Defender telemetry contains related terms in searchable fields."],
            references=threat.source_references,
            confidence=0.35,
        )
