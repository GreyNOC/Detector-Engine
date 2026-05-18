from __future__ import annotations

import pytest

from greynoc_detector_engine.models.detection import (
    DetectionKind,
    DetectionStatus,
    GeneratedDetection,
    ValidationEvidence,
    ValidationResult,
)
from greynoc_detector_engine.workers.jobs import DetectionLifecycleError, update_detection_status


class InMemoryDetectionStorage:
    def __init__(self, detection: GeneratedDetection | None = None) -> None:
        self.detections: dict[str, GeneratedDetection] = {}
        if detection:
            self.detections[detection.detection_id] = detection

    def get_detection(self, detection_id: str) -> GeneratedDetection | None:
        return self.detections.get(detection_id)

    def upsert_detection(self, record: GeneratedDetection) -> None:
        self.detections[record.detection_id] = record


def _draft_detection() -> GeneratedDetection:
    return GeneratedDetection(
        detection_id="det-test",
        related_threat_id="thr-test",
        kind=DetectionKind.SIGMA,
        title="Draft Test Detection",
        description="Test detection.",
        rule_query="title: test",
    )


def _passed_evidence() -> ValidationEvidence:
    return ValidationEvidence(
        result=ValidationResult.PASSED,
        summary="Validated against representative telemetry.",
        telemetry_source="splunk-lab",
        sample_size=100,
        true_positive_count=3,
        false_positive_count=0,
        reviewer="grey-soc",
    )


def test_update_detection_status_validates_detection_with_note_and_evidence() -> None:
    storage = InMemoryDetectionStorage(_draft_detection())

    result = update_detection_status(
        storage,  # type: ignore[arg-type]
        "det-test",
        DetectionStatus.VALIDATED,
        note="Validated against representative telemetry.",
        evidence=_passed_evidence(),
    )

    assert result.status == "ok"
    updated = storage.detections["det-test"]
    assert updated.status == DetectionStatus.VALIDATED
    assert "Validated against representative telemetry." in updated.validation_steps
    assert updated.validation_evidence[0].result == ValidationResult.PASSED
    assert updated.validation_evidence[0].false_positive_count == 0


def test_validated_detection_requires_passed_evidence() -> None:
    storage = InMemoryDetectionStorage(_draft_detection())

    with pytest.raises(DetectionLifecycleError):
        update_detection_status(  # type: ignore[arg-type]
            storage,
            "det-test",
            DetectionStatus.VALIDATED,
        )


def test_validated_detection_requires_reviewer_telemetry_and_sample_size() -> None:
    storage = InMemoryDetectionStorage(_draft_detection())
    incomplete = ValidationEvidence(
        result=ValidationResult.PASSED,
        summary="Incomplete validation evidence.",
    )

    with pytest.raises(DetectionLifecycleError):
        update_detection_status(  # type: ignore[arg-type]
            storage,
            "det-test",
            DetectionStatus.VALIDATED,
            evidence=incomplete,
        )


def test_deprecated_detection_requires_note_or_evidence() -> None:
    storage = InMemoryDetectionStorage(_draft_detection())

    with pytest.raises(DetectionLifecycleError):
        update_detection_status(  # type: ignore[arg-type]
            storage,
            "det-test",
            DetectionStatus.DEPRECATED,
        )


def test_update_detection_status_returns_not_found() -> None:
    storage = InMemoryDetectionStorage()

    result = update_detection_status(  # type: ignore[arg-type]
        storage,
        "det-missing",
        DetectionStatus.VALIDATED,
    )

    assert result.status == "not_found"
