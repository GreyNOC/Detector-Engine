from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from greynoc_detector_engine.detection.testing import DetectionTestReport
from greynoc_detector_engine.models.detection import (
    DetectionStatus,
    GeneratedDetection,
    ValidationResult,
)


class PassportGrade(StrEnum):
    UNPROVEN = "unproven"
    BRONZE = "bronze"
    SILVER = "silver"
    GOLD = "gold"
    PLATINUM = "platinum"


class DetectionQualityPassport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    detection_id: str
    grade: PassportGrade
    status: DetectionStatus
    evidence_count: int
    passed_evidence_count: int
    has_reviewer: bool
    has_telemetry_source: bool
    has_positive_sample: bool
    precision_ready: bool
    false_positive_total: int
    true_positive_total: int
    trust_score: float = Field(ge=0, le=100)
    blockers: list[str] = Field(default_factory=list)
    strengths: list[str] = Field(default_factory=list)


def build_detection_quality_passport(
    detection: GeneratedDetection,
    *,
    test_report: DetectionTestReport | None = None,
) -> DetectionQualityPassport:
    evidence = detection.validation_evidence
    passed = [item for item in evidence if item.result == ValidationResult.PASSED]
    has_reviewer = any(item.reviewer for item in passed)
    has_telemetry = any(item.telemetry_source for item in passed)
    has_positive_sample = any(
        item.sample_size is not None and item.sample_size > 0 for item in passed
    )
    false_positive_total = sum(item.false_positive_count or 0 for item in evidence)
    true_positive_total = sum(item.true_positive_count or 0 for item in evidence)
    precision_ready = bool(test_report and test_report.precision_ready)

    score = 0.0
    strengths: list[str] = []
    blockers: list[str] = []

    if detection.status == DetectionStatus.VALIDATED:
        score += 20
        strengths.append("Detection is validated.")
    else:
        blockers.append("Detection is not validated.")

    if passed:
        score += 20
        strengths.append("Passed validation evidence is present.")
    else:
        blockers.append("No passed validation evidence is present.")

    if has_reviewer:
        score += 10
        strengths.append("Validation evidence includes a reviewer.")
    else:
        blockers.append("Validation evidence lacks a reviewer.")

    if has_telemetry:
        score += 10
        strengths.append("Validation evidence includes a telemetry source.")
    else:
        blockers.append("Validation evidence lacks a telemetry source.")

    if has_positive_sample:
        score += 10
        strengths.append("Validation evidence includes a positive sample size.")
    else:
        blockers.append("Validation evidence lacks a positive sample size.")

    if precision_ready:
        score += 20
        strengths.append("Positive and negative fixtures passed.")
    else:
        blockers.append("No precision-ready test report is linked.")

    if false_positive_total == 0 and passed:
        score += 10
        strengths.append("No false positives are recorded in validation evidence.")
    elif false_positive_total > 0:
        blockers.append("False positives are recorded in validation evidence.")

    trust_score = round(min(100, score), 2)
    return DetectionQualityPassport(
        detection_id=detection.detection_id,
        grade=_grade(trust_score),
        status=detection.status,
        evidence_count=len(evidence),
        passed_evidence_count=len(passed),
        has_reviewer=has_reviewer,
        has_telemetry_source=has_telemetry,
        has_positive_sample=has_positive_sample,
        precision_ready=precision_ready,
        false_positive_total=false_positive_total,
        true_positive_total=true_positive_total,
        trust_score=trust_score,
        blockers=blockers,
        strengths=strengths,
    )


def _grade(score: float) -> PassportGrade:
    if score >= 95:
        return PassportGrade.PLATINUM
    if score >= 80:
        return PassportGrade.GOLD
    if score >= 60:
        return PassportGrade.SILVER
    if score >= 35:
        return PassportGrade.BRONZE
    return PassportGrade.UNPROVEN
