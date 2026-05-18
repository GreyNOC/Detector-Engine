from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from greynoc_detector_engine.cli.main import app
from greynoc_detector_engine.config.settings import get_settings


def test_cli_smoke_with_fixture_workflow(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("GREYNOC_DATABASE_PATH", str(tmp_path / "engine.sqlite"))
    get_settings.cache_clear()
    runner = CliRunner()

    init_result = runner.invoke(app, ["init"])
    cve_result = runner.invoke(
        app,
        ["ingest", "cve", "--fixture", "data/fixtures/cve_sample.json"],
    )
    kev_result = runner.invoke(
        app,
        ["ingest", "kev", "--fixture", "data/fixtures/kev_sample.json"],
    )
    correlate_result = runner.invoke(app, ["correlate"])
    list_result = runner.invoke(app, ["threats", "list"])

    assert init_result.exit_code == 0
    assert cve_result.exit_code == 0
    assert kev_result.exit_code == 0
    assert correlate_result.exit_code == 0
    assert list_result.exit_code == 0
    assert "CVE-2026-12345" in list_result.output
