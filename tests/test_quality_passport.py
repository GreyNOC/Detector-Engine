from __future__ import annotations

from greynoc_detector_engine.detection.testing import DetectionTestReport
from greynoc_detector_engine.intelligence.quality_passport import (
    PassportGrade,
    build_detection_quality_passport,
)
from greynoc_detector_engine.models.detection import (
    DetectionKind,
    DetectionStatus,
    GeneratedDetection,
    ValidationEvidence,
    ValidationResult,
)


def test_quality_passport_grades_validated_precision_ready_detection() -> None:
    detection = GeneratedDetection(
        detection_id="det-test",
        related_threat_id="thr-test",
        kind=DetectionKind.SIGMA,
        title="Validated Test Detection",
        description="Validated detection.",
        status=DetectionStatus.VALIDATED,
        rule_query="CommandLine contains CVE-2026-12345",
        validation_evidence=[
            ValidationEvidence(
                result=ValidationResult.PASSED,
                summary="Validated with no false positives.",
                telemetry_source="splunk-lab",
                sample_size=100,
                true_positive_count=3,
                false_positive_count=0,
                reviewer="grey-soc",
            )
        ],
    )
    report = DetectionTestReport(
        detection_id="det-test",
        total=2,
        passed=2,
        failed=0,
        precision_ready=True,
    )

    passport = build_detection_quality_passport(detection, test_report=report)

    assert passport.grade == PassportGrade.PLATINUM
    assert passport.trust_score == 100
    assert passport.precision_ready is True
    assert not passport.blockers


def test_quality_passport_flags_unproven_detection() -> None:
    detection = GeneratedDetection(
        detection_id="det-test",
        related_threat_id="thr-test",
        kind=DetectionKind.SIGMA,
        title="Draft Test Detection",
        description="Draft detection.",
        rule_query="CommandLine contains CVE-2026-12345",
    )

    passport = build_detection_quality_passport(detection)

    assert passport.grade == PassportGrade.UNPROVEN
    assert passport.trust_score == 0
    assert passport.blockers
