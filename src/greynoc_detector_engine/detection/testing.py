from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from greynoc_detector_engine.models.detection import GeneratedDetection


class DetectionFixtureExpectation(StrEnum):
    SHOULD_MATCH = "should_match"
    SHOULD_NOT_MATCH = "should_not_match"


class DetectionFixture(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=200)
    expectation: DetectionFixtureExpectation
    text: str = Field(min_length=1)
    metadata: dict[str, str] = Field(default_factory=dict)


class DetectionTestCase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    detection_id: str
    fixtures: list[DetectionFixture] = Field(default_factory=list)


class DetectionFixtureResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fixture_name: str
    expectation: DetectionFixtureExpectation
    matched: bool
    passed: bool
    reason: str


class DetectionTestReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    detection_id: str
    total: int
    passed: int
    failed: int
    precision_ready: bool
    results: list[DetectionFixtureResult] = Field(default_factory=list)


def run_detection_test_case(
    detection: GeneratedDetection,
    test_case: DetectionTestCase,
) -> DetectionTestReport:
    if detection.detection_id != test_case.detection_id:
        raise ValueError("Detection test case does not match detection id.")

    results = [_evaluate_fixture(detection, fixture) for fixture in test_case.fixtures]
    passed = sum(1 for result in results if result.passed)
    failed = len(results) - passed
    has_positive = any(
        fixture.expectation == DetectionFixtureExpectation.SHOULD_MATCH
        for fixture in test_case.fixtures
    )
    has_negative = any(
        fixture.expectation == DetectionFixtureExpectation.SHOULD_NOT_MATCH
        for fixture in test_case.fixtures
    )
    return DetectionTestReport(
        detection_id=detection.detection_id,
        total=len(results),
        passed=passed,
        failed=failed,
        precision_ready=failed == 0 and has_positive and has_negative,
        results=results,
    )


def _evaluate_fixture(
    detection: GeneratedDetection,
    fixture: DetectionFixture,
) -> DetectionFixtureResult:
    matched = _simple_text_match(detection, fixture.text)
    expected_match = fixture.expectation == DetectionFixtureExpectation.SHOULD_MATCH
    passed = matched is expected_match
    reason = (
        "Fixture matched as expected."
        if passed and expected_match
        else "Fixture did not match as expected."
        if passed
        else "Fixture unexpectedly matched."
        if matched
        else "Fixture unexpectedly did not match."
    )
    return DetectionFixtureResult(
        fixture_name=fixture.name,
        expectation=fixture.expectation,
        matched=matched,
        passed=passed,
        reason=reason,
    )


def _simple_text_match(detection: GeneratedDetection, text: str) -> bool:
    haystack = text.lower()
    terms = _candidate_terms(detection)
    return any(term in haystack for term in terms)


def _candidate_terms(detection: GeneratedDetection) -> set[str]:
    raw_terms = set()
    raw_terms.add(detection.related_threat_id)
    raw_terms.add(detection.title)
    raw_terms.add(detection.description)
    raw_terms.add(detection.rule_query)
    for reference in detection.references:
        if reference.title:
            raw_terms.add(reference.title)
        if reference.raw_excerpt:
            raw_terms.add(reference.raw_excerpt)
    terms: set[str] = set()
    for raw in raw_terms:
        for token in raw.replace("\"", " ").replace("'", " ").replace(":", " ").split():
            normalized = token.strip("[]{}(),.\\/|*+-_=<>!?").lower()
            if len(normalized) >= 6:
                terms.add(normalized)
    return terms
