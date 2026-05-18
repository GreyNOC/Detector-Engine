from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

import typer

from greynoc_detector_engine.config.settings import get_settings
from greynoc_detector_engine.ingest.base import IngestSourceUnavailable
from greynoc_detector_engine.utils.logging import configure_logging
from greynoc_detector_engine.workers.jobs import (
    build_storage,
    generate_detections_for_threat,
    initialize_project,
    run_correlation_job,
    run_ingest_job,
    run_score_job,
)

app = typer.Typer(help="GreyNOC Detector Engine defensive SOC-support CLI.")
ingest_app = typer.Typer(help="Ingest configured or fixture-backed sources.")
threats_app = typer.Typer(help="Inspect local threat-library records.")
detections_app = typer.Typer(help="Generate and inspect draft detections.")

app.add_typer(ingest_app, name="ingest")
app.add_typer(threats_app, name="threats")
app.add_typer(detections_app, name="detections")


@app.callback()
def main() -> None:
    settings = get_settings()
    configure_logging(settings.log_level)


@app.command("init")
def init_command() -> None:
    result = initialize_project(get_settings())
    typer.echo(result.model_dump_json())


@ingest_app.command("cve")
def ingest_cve(
    fixture: Path | None = typer.Option(None, "--fixture", exists=True, readable=True),
) -> None:
    _run_ingest("cve", fixture)


@ingest_app.command("kev")
def ingest_kev(
    fixture: Path | None = typer.Option(None, "--fixture", exists=True, readable=True),
) -> None:
    _run_ingest("kev", fixture)


@ingest_app.command("rss")
def ingest_rss(
    fixture: Path | None = typer.Option(None, "--fixture", exists=True, readable=True),
) -> None:
    _run_ingest("rss", fixture)


@app.command("correlate")
def correlate_command() -> None:
    result = run_correlation_job(build_storage(get_settings()))
    typer.echo(result.model_dump_json())


@app.command("score")
def score_command() -> None:
    result = run_score_job(build_storage(get_settings()))
    typer.echo(result.model_dump_json())


@threats_app.command("list")
def list_threats() -> None:
    storage = build_storage(get_settings())
    payload = [threat.model_dump(mode="json") for threat in storage.list_threats()]
    typer.echo(json.dumps(payload))


@threats_app.command("show")
def show_threat(threat_id: str) -> None:
    storage = build_storage(get_settings())
    threat = storage.get_threat(threat_id)
    if threat is None:
        typer.echo(f"Threat not found: {threat_id}", err=True)
        raise typer.Exit(1)
    typer.echo(threat.model_dump_json())


@detections_app.command("generate")
def generate_detection(threat_id: str) -> None:
    result = generate_detections_for_threat(build_storage(get_settings()), threat_id)
    if result.status == "not_found":
        typer.echo(f"Threat not found: {threat_id}", err=True)
        raise typer.Exit(1)
    typer.echo(result.model_dump_json())


@app.command("serve")
def serve_command(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8000, "--port"),
) -> None:
    import uvicorn

    uvicorn.run("greynoc_detector_engine.api.main:create_app", factory=True, host=host, port=port)


def _run_ingest(
    source: Literal["cve", "kev", "rss"],
    fixture: Path | None,
) -> None:
    settings = get_settings()
    storage = build_storage(settings)
    try:
        result = run_ingest_job(
            source=source,
            settings=settings,
            storage=storage,
            fixture_path=fixture,
        )
    except IngestSourceUnavailable as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(result.model_dump_json())


if __name__ == "__main__":
    app()
