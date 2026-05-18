from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from greynoc_detector_engine.cli.main import app
from greynoc_detector_engine.config.settings import Settings, get_settings
from greynoc_detector_engine.workers.jobs import build_storage
from greynoc_detector_engine.workers.workflow import (
    WorkflowDemoReport,
    run_workflow_demo,
)

FIXTURE_ROOT = Path(__file__).resolve().parents[2] / "data" / "fixtures"


@pytest.fixture()
def isolated_settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Settings:
    db_path = tmp_path / "engine.sqlite"
    data_dir = tmp_path / "data"
    monkeypatch.setenv("GREYNOC_DATABASE_PATH", str(db_path))
    monkeypatch.setenv("GREYNOC_DATA_DIR", str(data_dir))
    monkeypatch.setenv("GREYNOC_FIXTURE_ROOT", str(FIXTURE_ROOT))
    get_settings.cache_clear()
    settings = get_settings()
    yield settings
    get_settings.cache_clear()


def test_run_workflow_demo_uses_fixtures_and_reports_counts(
    isolated_settings: Settings,
) -> None:
    report = run_workflow_demo(isolated_settings)

    assert isinstance(report, WorkflowDemoReport)
    assert report.status in {"ok", "partial"}
    assert report.counts["cves"] >= 1
    assert report.counts["kev_entries"] >= 1
    assert report.counts["threats"] >= 1
    assert report.counts["ingest_runs"] >= 3
    assert {step.step for step in report.steps} >= {
        "init",
        "ingest:cve",
        "ingest:kev",
        "correlate",
        "predict",
        "generate-detections",
    }


def test_run_workflow_demo_skip_detections(isolated_settings: Settings) -> None:
    report = run_workflow_demo(
        isolated_settings,
        generate_detections=False,
    )

    step_names = {step.step for step in report.steps}
    assert "generate-detections" not in step_names


def test_run_workflow_demo_skips_missing_fixtures(
    isolated_settings: Settings, tmp_path: Path
) -> None:
    empty_root = tmp_path / "empty"
    empty_root.mkdir()

    report = run_workflow_demo(isolated_settings, fixture_root=empty_root)

    skipped_ingest = [step for step in report.steps if step.step.startswith("ingest:")]
    assert skipped_ingest
    assert all(step.status == "skipped" for step in skipped_ingest)
    assert report.counts["cves"] == 0
    assert report.counts["threats"] == 0


def test_workflow_demo_does_not_require_network(
    isolated_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Demo must complete without any live HTTP fetch.

    We sabotage the public HTTP client; any live attempt would raise.
    """

    def _explode(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Workflow demo attempted a live network fetch.")

    import httpx

    monkeypatch.setattr(httpx, "get", _explode)
    monkeypatch.setattr(httpx, "post", _explode)

    report = run_workflow_demo(isolated_settings)

    assert report.status in {"ok", "partial"}


def test_cli_workflow_demo_prints_summary(
    isolated_settings: Settings,
) -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["workflow", "demo"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["status"] in {"ok", "partial"}
    assert payload["counts"]["threats"] >= 1


def test_cli_workflow_demo_skip_detections(
    isolated_settings: Settings,
) -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["workflow", "demo", "--skip-detections"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    step_names = {step["step"] for step in payload["steps"]}
    assert "generate-detections" not in step_names


def test_cli_workflow_demo_writes_db_under_tmp(isolated_settings: Settings, tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["workflow", "demo"])

    assert result.exit_code == 0, result.output
    storage = build_storage(isolated_settings)
    assert len(storage.list_threats()) >= 1
    # No DB file leaked into the repo root: the configured database_path
    # lives under tmp_path because of the isolated_settings fixture.
    assert isolated_settings.database_path.parent.is_relative_to(tmp_path)
