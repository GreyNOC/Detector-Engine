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
    run_predict_job,
    run_score_job,
)

app = typer.Typer(help="GreyNOC Detector Engine defensive SOC-support CLI.")
ingest_app = typer.Typer(help="Ingest configured or fixture-backed sources.")
threats_app = typer.Typer(help="Inspect local threat-library records.")
detections_app = typer.Typer(help="Generate and inspect draft detections.")
predict_app = typer.Typer(help="Run the forward-looking predictive engine.")
network_app = typer.Typer(help="Passive local-network discovery and inventory.")
sensor_app = typer.Typer(help="Spacestation: lightweight intrusion sensor + darknet honeypot.")
feedback_app = typer.Typer(help="Submit analyst feedback that re-tunes predictive weights.")
export_app = typer.Typer(help="Export the threat library to STIX 2.1 or ATT&CK Navigator.")
doctor_app = typer.Typer(help="Engine self-diagnostic: safety defaults + source health.")

app.add_typer(ingest_app, name="ingest")
app.add_typer(threats_app, name="threats")
app.add_typer(detections_app, name="detections")
app.add_typer(predict_app, name="predict")
app.add_typer(network_app, name="network")
app.add_typer(sensor_app, name="sensor")
app.add_typer(feedback_app, name="feedback")
app.add_typer(export_app, name="export")
app.add_typer(doctor_app, name="doctor")


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


@ingest_app.command("epss")
def ingest_epss(
    fixture: Path | None = typer.Option(None, "--fixture", exists=True, readable=True),
) -> None:
    _run_ingest("epss", fixture)


@ingest_app.command("threatfox")
def ingest_threatfox(
    fixture: Path | None = typer.Option(None, "--fixture", exists=True, readable=True),
) -> None:
    _run_ingest("threatfox", fixture)


@ingest_app.command("urlhaus")
def ingest_urlhaus(
    fixture: Path | None = typer.Option(None, "--fixture", exists=True, readable=True),
) -> None:
    _run_ingest("urlhaus", fixture)


@ingest_app.command("ransomwatch")
def ingest_ransomwatch(
    fixture: Path | None = typer.Option(None, "--fixture", exists=True, readable=True),
) -> None:
    _run_ingest("ransomwatch", fixture)


@ingest_app.command("git")
def ingest_git(
    fixture: Path | None = typer.Option(
        None,
        "--fixture",
        exists=True,
        readable=True,
        help=(
            "Path to a directory that already contains a checked-out repository. "
            "When omitted, the engine will perform a shallow, allowlisted "
            "clone of the configured source URL (requires GREYNOC_FETCH_LIVE=true)."
        ),
    ),
) -> None:
    """Ingest defensive content from an allowlisted git repository."""
    _run_ingest("git", fixture)


@app.command("correlate")
def correlate_command(
    ransomware_posts_30d: int = typer.Option(0, "--ransomware-posts-30d"),
) -> None:
    result = run_correlation_job(
        build_storage(get_settings()), ransomware_posts_30d=ransomware_posts_30d
    )
    typer.echo(result.model_dump_json())


@app.command("score")
def score_command() -> None:
    result = run_score_job(build_storage(get_settings()))
    typer.echo(result.model_dump_json())


@predict_app.command("run")
def predict_run(
    asset_inventory: Path | None = typer.Option(
        None,
        "--asset-inventory",
        exists=True,
        readable=True,
        help="Path to a YAML file describing your asset inventory.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Recompute every forecast even when the stored input fingerprint is unchanged.",
    ),
) -> None:
    result = run_predict_job(
        build_storage(get_settings()),
        asset_inventory_path=asset_inventory,
        force=force,
    )
    typer.echo(result.model_dump_json())


@predict_app.command("forecasts")
def predict_forecasts(threat_id: str) -> None:
    storage = build_storage(get_settings())
    forecasts = storage.list_forecasts_for_threat(threat_id)
    typer.echo(json.dumps([f.model_dump(mode="json") for f in forecasts]))


@predict_app.command("campaigns")
def predict_campaigns() -> None:
    storage = build_storage(get_settings())
    campaigns = storage.list_campaigns()
    typer.echo(json.dumps([c.model_dump(mode="json") for c in campaigns]))


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


@network_app.command("discover")
def network_discover() -> None:
    """Read the OS ARP / neighbor table; persist devices and ICS classifications."""
    from greynoc_detector_engine.spacestation.orchestrator import run_discovery_job

    result = run_discovery_job(build_storage(get_settings()))
    typer.echo(result.model_dump_json())


@network_app.command("devices")
def network_devices() -> None:
    """List devices known to the local-network inventory."""
    storage = build_storage(get_settings())
    typer.echo(json.dumps([d.model_dump(mode="json") for d in storage.list_network_devices()]))


@network_app.command("ics")
def network_ics_observations() -> None:
    """List ICS protocol observations classified from passive discovery."""
    storage = build_storage(get_settings())
    typer.echo(json.dumps([o.model_dump(mode="json") for o in storage.list_ics_observations()]))


@sensor_app.command("run")
def sensor_run() -> None:
    """One-shot: snapshot OS connection table, detect scans, persist signals."""
    from greynoc_detector_engine.spacestation.orchestrator import run_sensor_job

    result = run_sensor_job(build_storage(get_settings()))
    typer.echo(result.model_dump_json())


@sensor_app.command("signals")
def sensor_signals() -> None:
    """List recent intrusion signals (port scans, knocks, darknet hits, ICS probes)."""
    storage = build_storage(get_settings())
    typer.echo(json.dumps([s.model_dump(mode="json") for s in storage.list_intrusion_signals()]))


@sensor_app.command("honeypot")
def sensor_honeypot(
    port: int = typer.Option(..., "--port", help="TCP port to bind."),
    bind_host: str = typer.Option("127.0.0.1", "--bind"),
    label: str = typer.Option("default-darknet", "--label"),
    capture_bytes: int = typer.Option(64, "--capture-bytes"),
    allow_external_bind: bool = typer.Option(
        False,
        "--allow-external-bind",
        help=(
            "Required when --bind is not loopback. "
            "Use only when intentionally exposing the listener."
        ),
    ),
) -> None:
    """Run the darknet TCP listener. Every connection is logged + cataloged.

    Ctrl+C to stop. The listener never speaks any protocol back.
    """
    import asyncio

    from greynoc_detector_engine.spacestation.honeypot import (
        DarknetHoneypot,
        HoneypotConfig,
    )

    storage = build_storage(get_settings())
    config = HoneypotConfig(
        label=label,
        bind_host=bind_host,
        port=port,
        capture_bytes=capture_bytes,
        allow_external_bind=allow_external_bind,
    )

    def on_event(event):  # type: ignore[no-untyped-def]
        storage.record_honeypot_event(event)
        typer.echo(event.model_dump_json())

    pot = DarknetHoneypot(config, on_event=on_event)

    async def runner() -> None:
        await pot.serve_forever()

    try:
        asyncio.run(runner())
    except KeyboardInterrupt:
        typer.echo('{"status":"stopped"}')


@feedback_app.command("submit")
def feedback_submit(
    threat_id: str,
    verdict: str = typer.Option(
        ...,
        "--verdict",
        help=("One of: true_positive, false_positive, benign_intent, duplicate, needs_context."),
    ),
    analyst: str = typer.Option("anonymous", "--analyst"),
    notes: str = typer.Option("", "--notes"),
) -> None:
    """Record analyst feedback. Re-runs tuner to update fusion weights."""
    from uuid import uuid4

    from greynoc_detector_engine.models.feedback import (
        AnalystVerdict,
        ThreatFeedback,
    )
    from greynoc_detector_engine.prediction.learning import FeedbackTuner

    storage = build_storage(get_settings())
    try:
        parsed_verdict = AnalystVerdict(verdict)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    feedback = ThreatFeedback(
        feedback_id=f"fb-{uuid4().hex[:12]}",
        threat_id=threat_id,
        verdict=parsed_verdict,
        analyst=analyst,
        notes=notes,
    )
    storage.upsert_threat_feedback(feedback)
    all_feedback = storage.list_threat_feedback()
    threats_by_id = {t.threat_id: t for t in storage.list_threats()}
    new_weights = FeedbackTuner().apply(all_feedback, threats_by_id)
    typer.echo(
        json.dumps(
            {
                "feedback_id": feedback.feedback_id,
                "verdict": parsed_verdict.value,
                "applied_weights": new_weights,
            }
        )
    )


@feedback_app.command("list")
def feedback_list() -> None:
    storage = build_storage(get_settings())
    typer.echo(json.dumps([fb.model_dump(mode="json") for fb in storage.list_threat_feedback()]))


@predict_app.command("counterfactual")
def predict_counterfactual(
    threat_id: str,
    intervention: str = typer.Option(
        ...,
        "--intervention",
        help=(
            "One of: patch_applied, ioc_blocked, segmented, detection_deployed. "
            "Can be repeated by separating with commas."
        ),
    ),
) -> None:
    """Run what-if analysis on a threat under one or more interventions."""
    from greynoc_detector_engine.prediction.counterfactual import (
        CounterfactualEngine,
        Intervention,
    )
    from greynoc_detector_engine.prediction.features import PredictiveContext

    storage = build_storage(get_settings())
    threat = storage.get_threat(threat_id)
    if threat is None:
        typer.echo(f"Threat not found: {threat_id}", err=True)
        raise typer.Exit(1)
    cve = storage.get_cve(threat.related_cves[0]) if threat.related_cves else None
    kev = storage.get_kev(threat.related_cves[0]) if threat.related_cves else None
    interventions: list[Intervention] = []
    for raw in intervention.split(","):
        raw = raw.strip()
        if not raw:
            continue
        try:
            interventions.append(Intervention(raw))
        except ValueError as exc:
            raise typer.BadParameter(str(exc)) from exc
    ctx = PredictiveContext(threat=threat, cve=cve, kev=kev)
    results = CounterfactualEngine().evaluate(ctx, interventions)
    typer.echo(json.dumps([r.model_dump(mode="json") for r in results]))


@predict_app.command("accuracy")
def predict_accuracy() -> None:
    """Compute calibration metrics over recorded forecast outcomes."""
    from greynoc_detector_engine.prediction.accuracy import compute_accuracy

    storage = build_storage(get_settings())
    outcomes = storage.list_forecast_outcomes()
    report = compute_accuracy(outcomes)
    typer.echo(report.model_dump_json())


@predict_app.command("record-outcome")
def predict_record_outcome(
    threat_id: str,
    verified_attack: bool = typer.Option(..., "--attack/--no-attack"),
    notes: str = typer.Option("", "--notes"),
) -> None:
    """Record whether a previously-forecast attack actually materialized."""
    storage = build_storage(get_settings())
    threat = storage.get_threat(threat_id)
    if threat is None or threat.attack_forecast is None:
        typer.echo(f"Threat or forecast not found: {threat_id}", err=True)
        raise typer.Exit(1)
    storage.record_forecast_outcome(
        threat_id=threat_id,
        forecast_probability=threat.attack_forecast.attack_probability,
        forecast_horizon=threat.attack_forecast.horizon.value,
        verified_attack=verified_attack,
        notes=notes,
    )
    typer.echo('{"status":"recorded"}')


@export_app.command("stix")
def export_stix(
    out: Path = typer.Option(..., "--out", help="Path to write the STIX 2.1 bundle JSON."),
) -> None:
    """Export the threat library + campaigns as a STIX 2.1 bundle."""
    from greynoc_detector_engine.exporters import StixExporter

    storage = build_storage(get_settings())
    bundle = StixExporter().export(
        threats=storage.list_threats(),
        campaigns=storage.list_campaigns(),
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(bundle.model_dump_json(indent=2), encoding="utf-8")
    typer.echo(json.dumps({"path": str(out), "objects": len(bundle.objects)}))


@export_app.command("attack-navigator")
def export_attack_navigator(
    out: Path = typer.Option(..., "--out", help="Path to write the Navigator layer JSON."),
) -> None:
    """Export an ATT&CK Navigator JSON layer colored by predicted probability."""
    from greynoc_detector_engine.exporters import AttackNavigatorExporter

    storage = build_storage(get_settings())
    layer = AttackNavigatorExporter().export(storage.list_threats())
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(layer.model_dump_json(indent=2), encoding="utf-8")
    typer.echo(json.dumps({"path": str(out), "techniques": len(layer.techniques)}))


@doctor_app.callback(invoke_without_command=True)
def doctor_root(ctx: typer.Context) -> None:
    """Run the safety self-check when invoked without a subcommand."""
    if ctx.invoked_subcommand is not None:
        return
    from greynoc_detector_engine.workers.health import (
        render_findings,
        run_safety_self_check,
    )

    report = run_safety_self_check()
    typer.echo(render_findings(report.findings))
    raise typer.Exit(report.exit_code)


@doctor_app.command("sources")
def doctor_sources() -> None:
    """Show recent ingest health per source."""
    from greynoc_detector_engine.workers.health import (
        render_findings,
        run_source_health,
    )

    storage = build_storage(get_settings())
    report = run_source_health(storage)
    typer.echo(render_findings(report.findings))
    raise typer.Exit(report.exit_code)


@app.command("serve")
def serve_command(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8000, "--port"),
) -> None:
    import uvicorn

    uvicorn.run("greynoc_detector_engine.api.main:create_app", factory=True, host=host, port=port)


def _run_ingest(
    source: Literal["cve", "kev", "rss", "epss", "threatfox", "urlhaus", "ransomwatch", "git"],
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
