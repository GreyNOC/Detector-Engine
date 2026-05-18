from __future__ import annotations

from greynoc_detector_engine.detection.testing import (
    DetectionFixture,
    DetectionFixtureExpectation,
    DetectionTestCase,
    run_detection_test_case,
)
from greynoc_detector_engine.models.detection import DetectionKind, GeneratedDetection


def test_detection_test_runner_reports_precision_ready() -> None:
    detection = GeneratedDetection(
        detection_id="det-test",
        related_threat_id="thr-cve-cve-2026-12345",
        kind=DetectionKind.SIGMA,
        title="Draft Sigma Hunt for CVE-2026-12345",
        description="Hunt for CVE-2026-12345 activity.",
        rule_query="CommandLine|contains: CVE-2026-12345",
    )
    test_case = DetectionTestCase(
        detection_id="det-test",
        fixtures=[
            DetectionFixture(
                name="positive",
                expectation=DetectionFixtureExpectation.SHOULD_MATCH,
                text="process command line contains CVE-2026-12345 scanner output",
            ),
            DetectionFixture(
                name="negative",
                expectation=DetectionFixtureExpectation.SHOULD_NOT_MATCH,
                text="routine backup job with no vulnerability terms",
            ),
        ],
    )

    report = run_detection_test_case(detection, test_case)

    assert report.total == 2
    assert report.failed == 0
    assert report.precision_ready is True


def test_detection_test_runner_flags_unexpected_match() -> None:
    detection = GeneratedDetection(
        detection_id="det-test",
        related_threat_id="thr-cve-cve-2026-12345",
        kind=DetectionKind.SIGMA,
        title="Draft Sigma Hunt for CVE-2026-12345",
        description="Hunt for CVE-2026-12345 activity.",
        rule_query="CommandLine|contains: CVE-2026-12345",
    )
    test_case = DetectionTestCase(
        detection_id="det-test",
        fixtures=[
            DetectionFixture(
                name="negative",
                expectation=DetectionFixtureExpectation.SHOULD_NOT_MATCH,
                text="CVE-2026-12345 appears in benign patch notes",
            ),
        ],
    )

    report = run_detection_test_case(detection, test_case)

    assert report.failed == 1
    assert report.precision_ready is False
