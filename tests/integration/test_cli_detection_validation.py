from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from greynoc_detector_engine.cli.main import app
from greynoc_detector_engine.config.settings import get_settings
from greynoc_detector_engine.models.detection import (
    DetectionKind,
    DetectionStatus,
    GeneratedDetection,
)
from greynoc_detector_engine.workers.jobs import build_storage


def _make_draft_detection(detection_id: str = "det-test") -> GeneratedDetection:
    return GeneratedDetection(
        detection_id=detection_id,
        related_threat_id="thr-test",
        kind=DetectionKind.SIGMA,
        title="Draft Test Detection",
        description="Test detection.",
        query="title: test",
    )


@pytest.fixture()
def isolated_storage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    db_path = tmp_path / "engine.sqlite"
    data_dir = tmp_path / "data"
    monkeypatch.setenv("GREYNOC_DATABASE_PATH", str(db_path))
    monkeypatch.setenv("GREYNOC_DATA_DIR", str(data_dir))
    get_settings.cache_clear()
    settings = get_settings()
    storage = build_storage(settings)
    yield storage
    get_settings.cache_clear()


def test_cli_validate_success_with_full_evidence(isolated_storage) -> None:
    isolated_storage.upsert_detection(_make_draft_detection())
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "detections",
            "validate",
            "det-test",
            "--telemetry-source",
            "splunk-lab",
            "--reviewer",
            "grey-soc",
            "--sample-size",
            "100",
            "--true-positives",
            "3",
            "--false-positives",
            "0",
            "--summary",
            "Validated with lab fixtures.",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["status"] == "ok"
    stored = isolated_storage.get_detection("det-test")
    assert stored is not None
    assert stored.status == DetectionStatus.VALIDATED
    assert stored.validation_evidence[-1].reviewer == "grey-soc"
    assert stored.validation_evidence[-1].telemetry_source == "splunk-lab"
    assert stored.validation_evidence[-1].sample_size == 100


def test_cli_validate_rejects_zero_sample_size(isolated_storage) -> None:
    isolated_storage.upsert_detection(_make_draft_detection())
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "detections",
            "validate",
            "det-test",
            "--telemetry-source",
            "splunk-lab",
            "--reviewer",
            "grey-soc",
            "--sample-size",
            "0",
            "--true-positives",
            "0",
            "--summary",
            "No samples available.",
        ],
    )

    assert result.exit_code != 0
    stored = isolated_storage.get_detection("det-test")
    assert stored is not None
    assert stored.status == DetectionStatus.DRAFT


def test_cli_validate_unknown_detection_id(isolated_storage) -> None:
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "detections",
            "validate",
            "det-missing",
            "--telemetry-source",
            "splunk-lab",
            "--reviewer",
            "grey-soc",
            "--sample-size",
            "5",
            "--true-positives",
            "1",
            "--summary",
            "Evidence.",
        ],
    )

    assert result.exit_code != 0
    assert "Detection not found" in result.output


def test_cli_reject_marks_detection_deprecated_with_reason(isolated_storage) -> None:
    isolated_storage.upsert_detection(_make_draft_detection())
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "detections",
            "reject",
            "det-test",
            "--reviewer",
            "grey-soc",
            "--reason",
            "Duplicated by better Sigma rule.",
        ],
    )

    assert result.exit_code == 0, result.output
    stored = isolated_storage.get_detection("det-test")
    assert stored is not None
    assert stored.status == DetectionStatus.DEPRECATED
    assert any("Duplicated" in evidence.summary for evidence in stored.validation_evidence)


def test_cli_reject_unknown_detection_id(isolated_storage) -> None:
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "detections",
            "reject",
            "det-missing",
            "--reviewer",
            "grey-soc",
            "--reason",
            "Unused.",
        ],
    )

    assert result.exit_code != 0
    assert "Detection not found" in result.output


def test_cli_quality_reports_passport_for_draft_detection(isolated_storage) -> None:
    isolated_storage.upsert_detection(_make_draft_detection())
    runner = CliRunner()

    result = runner.invoke(app, ["detections", "quality", "det-test"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["detection_id"] == "det-test"
    assert payload["status"] == "draft"
    assert payload["grade"] == "unproven"
    assert payload["trust_score"] == 0


def test_cli_quality_reports_validated_passport(isolated_storage) -> None:
    isolated_storage.upsert_detection(_make_draft_detection())
    runner = CliRunner()
    runner.invoke(
        app,
        [
            "detections",
            "validate",
            "det-test",
            "--telemetry-source",
            "splunk-lab",
            "--reviewer",
            "grey-soc",
            "--sample-size",
            "100",
            "--true-positives",
            "3",
            "--summary",
            "Validated with lab fixtures.",
        ],
    )

    result = runner.invoke(app, ["detections", "quality", "det-test"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["status"] == "validated"
    assert payload["evidence_count"] >= 1
    assert payload["has_reviewer"] is True
    assert payload["has_telemetry_source"] is True
    assert payload["trust_score"] >= 60


def test_cli_quality_unknown_detection_id(isolated_storage) -> None:
    runner = CliRunner()

    result = runner.invoke(app, ["detections", "quality", "det-missing"])

    assert result.exit_code != 0
    assert "Detection not found" in result.output
