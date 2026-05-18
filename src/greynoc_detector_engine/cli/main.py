from __future__ import annotations

import json
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, TypeVar

import typer

from greynoc_detector_engine.config.settings import get_settings
from greynoc_detector_engine.ingest.base import IngestSourceUnavailable
from greynoc_detector_engine.models.detection import (
    DetectionKind,
    DetectionStatus,
    GeneratedDetection,
)
from greynoc_detector_engine.models.threat import ThreatRecord, ThreatSeverity, ThreatStatus
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

DEFAULT_CLI_LIMIT = 100
MAX_CLI_LIMIT = 500
EnumT = TypeVar("EnumT", bound=StrEnum)
IngestCliSource = Literal[
    "cve",
    "kev",
    "rss",
    "epss",
    "threatfox",
    "urlhaus",
    "ransomwatch",
    "git",
]

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


@app.command("status")
def status_command(
    pretty: bool = typer.Option(False, "--pretty", help="Pretty-print JSON output."),
) -> None:
    """Show a compact local engine status summary."""
    storage = build_storage(get_settings())
    threats = storage.list_threats()
    detections = storage.list_detections()
    forecasts = sum(1 for threat in threats if threat.attack_forecast is not None)
    payload: dict[str, Any] = {
        "counts": {
            "cves": len(storage.list_cves()),
            "kev_entries": len(storage.list_kev()),
            "raw_items": len(storage.list_raw_items()),
            "threats": len(threats),
            "campaigns": len(storage.list_campaigns()),
            "detections": len(detections),
            "forecasts": forecasts,
            "network_devices": len(storage.list_network_devices()),
            "intrusion_signals": len(storage.list_intrusion_signals()),
            "honeypot_events": len(storage.list_honeypot_events()),
        },
        "detections_by_status": _count_by_value([d.status.value for d in detections]),
        "threats_by_severity": _count_by_value([t.severity.value for t in threats]),
        "latest_ingest_runs": [
            run.model_dump(mode="json") for run in storage.list_source_runs(limit=5)
        ],
    }
    _emit_json(payload, pretty=pretty)


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


@ingest_app.command("all")
def ingest_all(
    include_git: bool = typer.Option(
        False,
        "--include-git",
        help="Also ingest configured allowlisted git repositories.",
    ),
    continue_on_error: bool = typer.Option(
        True,
        "--continue-on-error/--stop-on-error",
        help="Continue with the next source if one source fails.",
    ),
    pretty: bool = typer.Option(False, "--pretty", help="Pretty-print JSON output."),
) -> None:
    """Run the standard defensive ingest sequence across configured sources."""
    settings = get_settings()
    storage = build_storage(settings)
    sources: list[IngestCliSource] = [
        "cve",
        "kev",
        "rss",
        "epss",
        "threatfox",
        "urlhaus",
        "ransomwatch",
    ]
    if include_git:
        sources.append("git")

    results: list[dict[str, Any]] = []
    failed = False
    for source in sources:
        try:
            result = run_ingest_job(source=source, settings=settings, storage=storage)
            results.append(result.model_dump(mode="json"))
        except Exception as exc:
            failed = True
            results.append({"job": f"ingest:{source}", "status": "failed", "error": str(exc)})
            if not continue_on_error:
                break

    _emit_json({"status": "failed" if failed else "ok", "results": results}, pretty=pretty)
    if failed:
        raise typer.Exit(1)


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
def predict_forecasts(
    threat_id: str,
    limit: int = typer.Option(DEFAULT_CLI_LIMIT, "--limit", min=1, max=MAX_CLI_LIMIT),
    pretty: bool = typer.Option(False, "--pretty", help="Pretty-print JSON output."),
) -> None:
    storage = build_storage(get_settings())
    forecasts = storage.list_forecasts_for_threat(threat_id)[:limit]
    _emit_json([f.model_dump(mode="json") for f in forecasts], pretty=pretty)


@predict_app.command("campaigns")
def predict_campaigns(
    limit: int = typer.Option(DEFAULT_CLI_LIMIT, "--limit", min=1, max=MAX_CLI_LIMIT),
    pretty: bool = typer.Option(False, "--pretty", help="Pretty-print JSON output."),
) -> None:
    storage = build_storage(get_settings())
    campaigns = storage.list_campaigns()[:limit]
    _emit_json([c.model_dump(mode="json") for c in campaigns], pretty=pretty)


@predict_app.command("imminent")
def predict_imminent(
    min_probability: float = typer.Option(0.5, "--min-probability", min=0.0, max=1.0),
    limit: int = typer.Option(DEFAULT_CLI_LIMIT, "--limit", min=1, max=MAX_CLI_LIMIT),
    pretty: bool = typer.Option(False, "--pretty", help="Pretty-print JSON output."),
) -> None:
    """List forecasted imminent or near-term threats above a probability threshold."""
    storage = build_storage(get_settings())
    rows: list[dict[str, Any]] = []
    for threat in storage.list_threats():
        forecast = threat.attack_forecast
        if forecast is None:
            continue
        if forecast.horizon.value not in {"imminent", "near_term"}:
            continue
        if forecast.attack_probability < min_probability:
            continue
        rows.append(_threat_summary(threat))
    rows.sort(key=lambda row: float(row.get("attack_probability") or 0.0), reverse=True)
    _emit_json(rows[:limit], pretty=pretty)


@threats_app.command("list")
def list_threats(
    severity: str | None = typer.Option(None, "--severity", help="Filter by severity."),
    status: str | None = typer.Option(None, "--status", help="Filter by threat status."),
    limit: int = typer.Option(DEFAULT_CLI_LIMIT, "--limit", min=1, max=MAX_CLI_LIMIT),
    summary: bool = typer.Option(False, "--summary", help="Return compact threat summaries."),
    pretty: bool = typer.Option(False, "--pretty", help="Pretty-print JSON output."),
) -> None:
    storage = build_storage(get_settings())
    threats = storage.list_threats()
    if severity is not None:
        parsed_severity = _parse_enum(ThreatSeverity, severity, "severity")
        threats = [threat for threat in threats if threat.severity == parsed_severity]
    if status is not None:
        parsed_status = _parse_enum(ThreatStatus, status, "status")
        threats = [threat for threat in threats if threat.status == parsed_status]
    threats = threats[:limit]
    payload: Any
    if summary:
        payload = [_threat_summary(threat) for threat in threats]
    else:
        payload = [threat.model_dump(mode="json") for threat in threats]
    _emit_json(payload, pretty=pretty)


@threats_app.command("top")
def top_threats(
    limit: int = typer.Option(10, "--limit", min=1, max=MAX_CLI_LIMIT),
    min_probability: float = typer.Option(0.0, "--min-probability", min=0.0, max=1.0),
    pretty: bool = typer.Option(False, "--pretty", help="Pretty-print JSON output."),
) -> None:
    """Show the highest-priority threats by forecast probability and severity."""
    storage = build_storage(get_settings())
    rows = [_threat_summary(threat) for threat in storage.list_threats()]
    rows = [row for row in rows if float(row.get("attack_probability") or 0.0) >= min_probability]
    rows.sort(key=_threat_priority_sort_key, reverse=True)
    _emit_json(rows[:limit], pretty=pretty)


@threats_app.command("show")
def show_threat(
    threat_id: str,
    pretty: bool = typer.Option(False, "--pretty", help="Pretty-print JSON output."),
) -> None:
    storage = build_storage(get_settings())
    threat = storage.get_threat(threat_id)
    if threat is None:
        typer.echo(f"Threat not found: {threat_id}", err=True)
        raise typer.Exit(1)
    _emit_json(threat.model_dump(mode="json"), pretty=pretty)


@detections_app.command("generate")
def generate_detection(threat_id: str) -> None:
    result = generate_detections_for_threat(build_storage(get_settings()), threat_id)
    if result.status == "not_found":
        typer.echo(f"Threat not found: {threat_id}", err=True)
        raise typer.Exit(1)
    typer.echo(result.model_dump_json())


@detections_app.command("list")
def list_detections(
    status: str | None = typer.Option(None, "--status", help="Filter by detection status."),
    kind: str | None = typer.Option(None, "--kind", help="Filter by detection kind."),
    threat_id: str | None = typer.Option(None, "--threat-id", help="Filter by related threat."),
    limit: int = typer.Option(DEFAULT_CLI_LIMIT, "--limit", min=1, max=MAX_CLI_LIMIT),
    summary: bool = typer.Option(False, "--summary", help="Return compact detection summaries."),
    pretty: bool = typer.Option(False, "--pretty", help="Pretty-print JSON output."),
) -> None:
    """List generated detections with optional defensive-review filters."""
    storage = build_storage(get_settings())
    detections = storage.list_detections()
    if status is not None:
        parsed_status = _parse_enum(DetectionStatus, status, "status")
        detections = [detection for detection in detections if detection.status == parsed_status]
    if kind is not None:
        parsed_kind = _parse_enum(DetectionKind, kind, "kind")
        detections = [detection for detection in detections if detection.kind == parsed_kind]
    if threat_id is not None:
        detections = [
            detection
            for detection in detections
            if detection.related_threat_id == threat_id
        ]
    detections = detections[:limit]
    payload: Any
    if summary:
        payload = [_detection_summary(detection) for detection in detections]
    else:
        payload = [detection.model_dump(mode="json") for detection in detections]
    _emit_json(payload, pretty=pretty)


@detections_app.command("show")
def show_detection(
    detection_id: str,
    pretty: bool = typer.Option(False, "--pretty", help="Pretty-print JSON output."),
) -> None:
    """Show one generated detection by ID."""
    storage = build_storage(get_settings())
    detection = storage.get_detection(detection_id)
    if detection is None:
        typer.echo(f"Detection not found: {detection_id}", err=True)
        raise typer.Exit(1)
    _emit_json(detection.model_dump(mode="json"), pretty=pretty)


@network_app.command("discover")
def network_discover() -> None:
    """Read the OS ARP / neighbor table; persist devices and ICS classifications."""
    from greynoc_detector_engine.spacestation.orchestrator import run_discovery_job

    result = run_discovery_job(build_storage(get_settings()))
    typer.echo(result.model_dump_json())


@network_app.command("devices")
def network_devices(
    limit: int = typer.Option(DEFAULT_CLI_LIMIT, "--limit", min=1, max=MAX_CLI_LIMIT),
    pretty: bool = typer.Option(False, "--pretty", help="Pretty-print JSON output."),
) -> None:
    """List devices known to the local-network inventory."""
    storage = build_storage(get_settings())
    _emit_json(
        [d.model_dump(mode="json") for d in storage.list_network_devices()[:limit]],
        pretty=pretty,
    )


@network_app.command("ics")
def network_ics_observations(
    limit: int = typer.Option(DEFAULT_CLI_LIMIT, "--limit", min=1, max=MAX_CLI_LIMIT),
    pretty: bool = typer.Option(False, "--pretty", help="Pretty-print JSON output."),
) -> None:
    """List ICS protocol observations classified from passive discovery."""
    storage = build_storage(get_settings())
    _emit_json(
        [o.model_dump(mode="json") for o in storage.list_ics_observations()[:limit]],
        pretty=pretty,
    )


@sensor_app.command("run")
def sensor_run() -> None:
    """One-shot: snapshot OS connection table, detect scans, persist signals."""
    from greynoc_detector_engine.spacestation.orchestrator import run_sensor_job

    result = run_sensor_job(build_storage(get_settings()))
    typer.echo(result.model_dump_json())


@sensor_app.command("signals")
def sensor_signals(
    limit: int = typer.Option(DEFAULT_CLI_LIMIT, "--limit", min=1, max=MAX_CLI_LIMIT),
    pretty: bool = typer.Option(False, "--pretty", help="Pretty-print JSON output."),
) -> None:
    """List recent intrusion signals (port scans, knocks, darknet hits, ICS probes)."""
    storage = build_storage(get_settings())
    _emit_json(
        [s.model_dump(mode="json") for s in storage.list_intrusion_signals()[:limit]],
        pretty=pretty,
    )


@sensor_app.command("honeypot-events")
def sensor_honeypot_events(
    limit: int = typer.Option(DEFAULT_CLI_LIMIT, "--limit", min=1, max=MAX_CLI_LIMIT),
    pretty: bool = typer.Option(False, "--pretty", help="Pretty-print JSON output."),
) -> None:
    """List captured darknet honeypot events."""
    storage = build_storage(get_settings())
    _emit_json(
        [event.model_dump(mode="json") for event in storage.list_honeypot_events()[:limit]],
        pretty=pretty,
    )


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

    def on_event(event: Any) -> None:
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
    _emit_json(
        {
            "feedback_id": feedback.feedback_id,
            "verdict": parsed_verdict.value,
            "applied_weights": new_weights,
        }
    )


@feedback_app.command("list")
def feedback_list(
    limit: int = typer.Option(DEFAULT_CLI_LIMIT, "--limit", min=1, max=MAX_CLI_LIMIT),
    pretty: bool = typer.Option(False, "--pretty", help="Pretty-print JSON output."),
) -> None:
    storage = build_storage(get_settings())
    _emit_json(
        [fb.model_dump(mode="json") for fb in storage.list_threat_feedback()[:limit]],
        pretty=pretty,
    )


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


def _run_ingest(source: IngestCliSource, fixture: Path | None) -> None:
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


def _emit_json(payload: Any, *, pretty: bool = False) -> None:
    indent = 2 if pretty else None
    typer.echo(json.dumps(payload, indent=indent, sort_keys=pretty))


def _count_by_value(values: list[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return counts


def _parse_enum(enum_type: type[EnumT], raw: str, name: str) -> EnumT:
    try:
        return enum_type(raw)
    except ValueError as exc:
        allowed = ", ".join(item.value for item in enum_type)
        raise typer.BadParameter(f"Invalid {name}: {raw}. Expected one of: {allowed}") from exc


def _threat_summary(threat: ThreatRecord) -> dict[str, Any]:
    forecast = threat.attack_forecast
    predictive_score = threat.predictive_score
    return {
        "threat_id": threat.threat_id,
        "title": threat.title,
        "severity": threat.severity.value,
        "status": threat.status.value,
        "confidence": threat.confidence,
        "predictive_score": predictive_score.score if predictive_score is not None else None,
        "attack_probability": forecast.attack_probability if forecast is not None else None,
        "horizon": forecast.horizon.value if forecast is not None else None,
        "related_cves": threat.related_cves,
        "campaign_ids": threat.campaign_ids,
        "recommended_soc_actions": threat.recommended_soc_actions[:5],
    }


def _detection_summary(detection: GeneratedDetection) -> dict[str, Any]:
    return {
        "detection_id": detection.detection_id,
        "related_threat_id": detection.related_threat_id,
        "kind": detection.kind.value,
        "status": detection.status.value,
        "title": detection.title,
        "confidence": detection.confidence,
        "required_telemetry": detection.required_telemetry,
    }


def _threat_priority_sort_key(row: dict[str, Any]) -> tuple[float, float, float]:
    severity_weight = {
        "critical": 4.0,
        "high": 3.0,
        "medium": 2.0,
        "low": 1.0,
    }.get(str(row.get("severity")), 0.0)
    attack_probability = float(row.get("attack_probability") or 0.0)
    predictive_score = float(row.get("predictive_score") or 0.0)
    return (attack_probability, severity_weight, predictive_score)


if __name__ == "__main__":
    app()
