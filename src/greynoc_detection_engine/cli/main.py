from __future__ import annotations

from pathlib import Path

import typer

from greynoc_detection_engine.config.settings import get_settings
from greynoc_detection_engine.ingest.base import IngestSourceUnavailable
from greynoc_detection_engine.utils.logging import configure_logging
from greynoc_detection_engine.workers.jobs import (
    IngestSourceName,
    build_storage,
    generate_detections_for_all,
    generate_detections_for_threat,
    initialize_project,
    run_correlation_job,
    run_ingest_job,
    run_score_job,
)

app = typer.Typer(help="GreyNOC defensive detection-engine CLI.")


@app.callback()
def main() -> None:
    settings = get_settings()
    configure_logging(settings.log_level)


@app.command("init")
def init_command() -> None:
    result = initialize_project(get_settings())
    typer.echo(result.model_dump_json())


@app.command("ingest")
def ingest_command(
    source: IngestSourceName = typer.Option(..., "--source"),
    fixture: Path | None = typer.Option(None, "--fixture", exists=True, readable=True),
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


@app.command("correlate")
def correlate_command() -> None:
    result = run_correlation_job(build_storage(get_settings()))
    typer.echo(result.model_dump_json())


@app.command("score")
def score_command() -> None:
    result = run_score_job(build_storage(get_settings()))
    typer.echo(result.model_dump_json())


@app.command("generate-detections")
def generate_detections_command(threat_id: str | None = typer.Option(None, "--threat-id")) -> None:
    storage = build_storage(get_settings())
    result = (
        generate_detections_for_threat(storage, threat_id)
        if threat_id
        else generate_detections_for_all(storage)
    )
    typer.echo(result.model_dump_json())


@app.command("serve")
def serve_command(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8000, "--port"),
) -> None:
    import uvicorn

    uvicorn.run("greynoc_detection_engine.api.main:create_app", factory=True, host=host, port=port)


if __name__ == "__main__":
    app()
