from __future__ import annotations

from greynoc_detector_engine.detection.export import (
    build_detection_export_bundle,
    render_detection_export_bundle,
)
from greynoc_detector_engine.models.detection import (
    DetectionKind,
    DetectionStatus,
    GeneratedDetection,
    ValidationEvidence,
    ValidationResult,
)


def _detection(status: DetectionStatus, kind: DetectionKind) -> GeneratedDetection:
    return GeneratedDetection(
        detection_id=f"det-{status.value}-{kind.value}",
        related_threat_id="thr-test",
        kind=kind,
        title="Test Detection",
        description="Test export detection.",
        status=status,
        required_telemetry=["process creation"],
        rule_query="CommandLine contains CVE-2026-12345",
        validation_evidence=[
            ValidationEvidence(
                result=ValidationResult.PASSED,
                summary="Validated.",
                telemetry_source="splunk-lab",
                sample_size=10,
                reviewer="grey-soc",
            )
        ],
    )


def test_export_bundle_defaults_to_validated_detections() -> None:
    draft = _detection(DetectionStatus.DRAFT, DetectionKind.SIGMA)
    validated = _detection(DetectionStatus.VALIDATED, DetectionKind.SIGMA)

    bundle = build_detection_export_bundle([draft, validated])

    assert bundle.count == 1
    assert bundle.detections[0].status == DetectionStatus.VALIDATED
    assert bundle.detections_by_kind == {"sigma": 1}


def test_export_bundle_text_contains_rule_and_evidence() -> None:
    validated = _detection(DetectionStatus.VALIDATED, DetectionKind.SIGMA)
    bundle = build_detection_export_bundle([validated])

    rendered = render_detection_export_bundle(bundle, export_format="text")

    assert "CommandLine contains CVE-2026-12345" in rendered
    assert "passed: Validated." in rendered
