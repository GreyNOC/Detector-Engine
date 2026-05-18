from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from greynoc_detector_engine.api.main import create_app
from greynoc_detector_engine.cli.main import app
from greynoc_detector_engine.config.settings import get_settings
from greynoc_detector_engine.models.job import JobHistoryEntry, JobStatus
from greynoc_detector_engine.workers.jobs import build_storage, record_job

FIXTURE_ROOT = Path(__file__).resolve().parents[2] / "data" / "fixtures"


@pytest.fixture()
def isolated_settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    db_path = tmp_path / "engine.sqlite"
    data_dir = tmp_path / "data"
    monkeypatch.setenv("GREYNOC_DATABASE_PATH", str(db_path))
    monkeypatch.setenv("GREYNOC_DATA_DIR", str(data_dir))
    monkeypatch.setenv("GREYNOC_FIXTURE_ROOT", str(FIXTURE_ROOT))
    get_settings.cache_clear()
    yield get_settings()
    get_settings.cache_clear()


def test_record_job_marks_completed_on_success(isolated_settings) -> None:
    storage = build_storage(isolated_settings)

    with record_job(storage, "test:noop") as summary:
        summary["touched"] = 1

    entries = storage.list_job_history()
    assert len(entries) == 1
    entry = entries[0]
    assert entry.job_type == "test:noop"
    assert entry.status == JobStatus.COMPLETED
    assert entry.finished_at is not None
    assert entry.result_summary == {"touched": 1}
    assert entry.error is None


def test_record_job_marks_failed_on_exception(isolated_settings) -> None:
    storage = build_storage(isolated_settings)

    with pytest.raises(RuntimeError), record_job(storage, "test:boom") as summary:
        summary["partial"] = 0
        raise RuntimeError("kaboom")

    entries = storage.list_job_history()
    assert len(entries) == 1
    entry = entries[0]
    assert entry.status == JobStatus.FAILED
    assert entry.error == "kaboom"
    assert entry.finished_at is not None
    assert entry.result_summary == {"partial": 0}


def test_job_history_entry_rejects_finished_before_started() -> None:
    from greynoc_detector_engine.utils.time import utc_now

    started = utc_now()
    with pytest.raises(ValueError):
        JobHistoryEntry(
            job_type="test:bad",
            status=JobStatus.COMPLETED,
            started_at=started,
            finished_at=started.replace(year=started.year - 1),
        )


def test_job_history_failed_requires_error() -> None:
    with pytest.raises(ValueError):
        JobHistoryEntry(
            job_type="test:bad",
            status=JobStatus.FAILED,
        )


def test_workflow_demo_records_job_history(isolated_settings) -> None:
    from greynoc_detector_engine.workers.workflow import run_workflow_demo

    run_workflow_demo(isolated_settings)
    storage = build_storage(isolated_settings)

    entries = storage.list_job_history()
    job_types = {entry.job_type for entry in entries}

    assert {
        "workflow:init",
        "ingest:cve",
        "ingest:kev",
        "correlate",
        "predict",
        "generate-detections",
    } <= job_types
    for entry in entries:
        assert entry.status in {JobStatus.COMPLETED, JobStatus.SKIPPED, JobStatus.FAILED}
        if entry.status == JobStatus.COMPLETED:
            assert entry.finished_at is not None


def test_cli_jobs_list_and_show(isolated_settings) -> None:
    runner = CliRunner()
    workflow_result = runner.invoke(app, ["workflow", "demo"])
    assert workflow_result.exit_code == 0, workflow_result.output

    list_result = runner.invoke(app, ["jobs", "list"])
    assert list_result.exit_code == 0, list_result.output
    payload = json.loads(list_result.output)
    assert payload, "Expected at least one job-history entry"
    job_id = payload[0]["job_id"]

    show_result = runner.invoke(app, ["jobs", "show", job_id])
    assert show_result.exit_code == 0, show_result.output
    entry = json.loads(show_result.output)
    assert entry["job_id"] == job_id


def test_cli_jobs_list_filters_by_job_type(isolated_settings) -> None:
    runner = CliRunner()
    runner.invoke(app, ["workflow", "demo"])

    result = runner.invoke(app, ["jobs", "list", "--job-type", "correlate"])

    assert result.exit_code == 0, result.output
    entries = json.loads(result.output)
    assert entries
    assert all(entry["job_type"] == "correlate" for entry in entries)


def test_cli_jobs_show_unknown_id(isolated_settings) -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["jobs", "show", "job-missing"])

    assert result.exit_code != 0
    assert "Job not found" in result.output


def test_api_jobs_endpoints(isolated_settings) -> None:
    runner = CliRunner()
    runner.invoke(app, ["workflow", "demo"])

    client = TestClient(create_app())

    list_response = client.get("/jobs")
    assert list_response.status_code == 200
    entries = list_response.json()
    assert entries
    job_id = entries[0]["job_id"]

    detail_response = client.get(f"/jobs/{job_id}")
    assert detail_response.status_code == 200
    assert detail_response.json()["job_id"] == job_id

    missing_response = client.get("/jobs/job-missing")
    assert missing_response.status_code == 404


def test_api_jobs_list_respects_limit_bounds(isolated_settings) -> None:
    client = TestClient(create_app())

    too_large = client.get("/jobs", params={"limit": 1000})
    assert too_large.status_code == 422

    too_small = client.get("/jobs", params={"limit": 0})
    assert too_small.status_code == 422
