from __future__ import annotations

from greynoc_detection_engine.detection.generators import DetectionGeneratorSuite
from greynoc_detection_engine.models.threat import ThreatRecord


def test_detection_suite_generates_drafts_only() -> None:
    threat = ThreatRecord(
        threat_id="thr-test",
        title="CVE-2026-12345 ExampleCorp Gateway",
        summary="Example defensive metadata.",
        category="vulnerability",
        related_cves=["CVE-2026-12345"],
    )
    detections = DetectionGeneratorSuite().generate_all(threat)
    assert {detection.kind.value for detection in detections} == {
        "sigma",
        "yara",
        "suricata",
        "splunk",
        "elastic",
        "defender",
    }
    assert all(detection.status == "draft" for detection in detections)
    assert "condition:\n        false" in detections[1].query
