from __future__ import annotations

import json
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, TypeVar

import typer

if TYPE_CHECKING:
    from greynoc_detector_engine.crypto import HybridSigner
    from greynoc_detector_engine.eval.corpus import ForecastCorpusStats, ForecastExample

from greynoc_detector_engine.catalog.threat_query import (
    ThreatQueryFilters,
    ThreatSort,
    filter_threats,
    summarize_threat,
)
from greynoc_detector_engine.config.settings import get_settings
from greynoc_detector_engine.ingest.base import IngestSourceUnavailable
from greynoc_detector_engine.models.detection import (
    DetectionKind,
    DetectionStatus,
    GeneratedDetection,
)
from greynoc_detector_engine.models.prediction import ForecastHorizon
from greynoc_detector_engine.models.threat import (
    AIAttackType,
    ThreatRecord,
    ThreatSeverity,
    ThreatStatus,
)
from greynoc_detector_engine.utils.logging import configure_logging
from greynoc_detector_engine.workers.jobs import (
    build_storage,
    generate_detections_for_threat,
    initialize_project,
    record_job,
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
workflow_app = typer.Typer(help="Repeatable operator workflows (golden path demo, etc.).")
jobs_app = typer.Typer(help="Inspect orchestrated worker job history.")
eval_app = typer.Typer(help="Offline forecast-quality evaluation (metrics, calibration, weights).")
quantum_app = typer.Typer(help="Post-quantum / harvest-now-decrypt-later threat assessment.")
crypto_app = typer.Typer(
    help="Post-quantum crypto: keys, signing, KEM encryption, CBOM, transparency log."
)
crypto_log_app = typer.Typer(help="Tamper-evident, PQ-signed Merkle transparency log of artifacts.")
crypto_app.add_typer(crypto_log_app, name="log")

app.add_typer(ingest_app, name="ingest")
app.add_typer(threats_app, name="threats")
app.add_typer(detections_app, name="detections")
app.add_typer(predict_app, name="predict")
app.add_typer(network_app, name="network")
app.add_typer(sensor_app, name="sensor")
app.add_typer(feedback_app, name="feedback")
app.add_typer(export_app, name="export")
app.add_typer(doctor_app, name="doctor")
app.add_typer(workflow_app, name="workflow")
app.add_typer(jobs_app, name="jobs")
app.add_typer(eval_app, name="eval")
app.add_typer(quantum_app, name="quantum")
app.add_typer(crypto_app, name="crypto")


@app.callback()
def main() -> None:
    settings = get_settings()
    configure_logging(settings.log_level)


@app.command("init")
def init_command() -> None:
    result = initialize_project(get_settings())
    typer.echo(result.model_dump_json())


@jobs_app.command("list")
def jobs_list(
    job_type: str | None = typer.Option(
        None, "--job-type", help="Filter by job type (e.g. ingest:cve)."
    ),
    limit: int = typer.Option(DEFAULT_CLI_LIMIT, "--limit", min=1, max=MAX_CLI_LIMIT),
    pretty: bool = typer.Option(False, "--pretty", help="Pretty-print JSON output."),
) -> None:
    """List recent job-history entries (most recent first)."""
    storage = build_storage(get_settings())
    entries = storage.list_job_history(job_type=job_type, limit=limit)
    _emit_json([entry.model_dump(mode="json") for entry in entries], pretty=pretty)


@jobs_app.command("show")
def jobs_show(
    job_id: str,
    pretty: bool = typer.Option(False, "--pretty", help="Pretty-print JSON output."),
) -> None:
    """Show one job-history entry by job_id."""
    storage = build_storage(get_settings())
    entry = storage.get_job_history(job_id)
    if entry is None:
        typer.echo(f"Job not found: {job_id}", err=True)
        raise typer.Exit(1)
    _emit_json(entry.model_dump(mode="json"), pretty=pretty)


@workflow_app.command("demo")
def workflow_demo(
    fixture_root: Path | None = typer.Option(
        None,
        "--fixture-root",
        exists=True,
        readable=True,
        file_okay=False,
        dir_okay=True,
        help="Override the directory containing fixture sources.",
    ),
    skip_detections: bool = typer.Option(
        False,
        "--skip-detections",
        help="Skip the draft-detection generation step.",
    ),
    pretty: bool = typer.Option(False, "--pretty", help="Pretty-print JSON output."),
) -> None:
    """Run the local golden-path workflow against bundled fixtures.

    Fully offline by default. The command initializes local paths, ingests
    fixture-backed sources, correlates weak signals, runs the predictive
    layer, and (unless ``--skip-detections``) generates draft detections.
    It prints a compact JSON summary at the end.
    """
    from greynoc_detector_engine.workers.workflow import run_workflow_demo

    settings = get_settings()
    report = run_workflow_demo(
        settings,
        fixture_root=fixture_root,
        generate_detections=not skip_detections,
    )
    _emit_json(report.model_dump(mode="json"), pretty=pretty)
    if report.status == "failed":
        raise typer.Exit(1)


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
            with record_job(storage, f"ingest:{source}") as summary:
                result = run_ingest_job(source=source, settings=settings, storage=storage)
                summary.update(result.counts)
                summary["status"] = result.status
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
    storage = build_storage(get_settings())
    with record_job(storage, "correlate") as summary:
        result = run_correlation_job(storage, ransomware_posts_30d=ransomware_posts_30d)
        summary.update(result.counts)
    typer.echo(result.model_dump_json())


@app.command("score")
def score_command() -> None:
    storage = build_storage(get_settings())
    with record_job(storage, "score") as summary:
        result = run_score_job(storage)
        summary.update(result.counts)
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
    storage = build_storage(get_settings())
    with record_job(storage, "predict") as summary:
        result = run_predict_job(
            storage,
            asset_inventory_path=asset_inventory,
            force=force,
        )
        summary.update(result.counts)
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
    query: str | None = typer.Option(
        None,
        "--query",
        "-q",
        help=(
            "Case-insensitive search across title, summary, CVEs, products, actors, "
            "sectors, and evidence."
        ),
    ),
    severity: str | None = typer.Option(None, "--severity", help="Filter by severity."),
    status: str | None = typer.Option(None, "--status", help="Filter by threat status."),
    cve: str | None = typer.Option(None, "--cve", help="Filter by exact related CVE ID."),
    product: str | None = typer.Option(
        None,
        "--product",
        help="Filter by affected product substring.",
    ),
    actor: str | None = typer.Option(None, "--actor", help="Filter by suspected actor substring."),
    sector: str | None = typer.Option(None, "--sector", help="Filter by sector substring."),
    campaign: str | None = typer.Option(None, "--campaign", help="Filter by exact campaign ID."),
    horizon: str | None = typer.Option(None, "--horizon", help="Filter by forecast horizon."),
    ai_attack_type: str | None = typer.Option(
        None,
        "--ai-attack-type",
        help="Filter by AI attack taxonomy value.",
    ),
    min_probability: float | None = typer.Option(
        None,
        "--min-probability",
        min=0.0,
        max=1.0,
        help="Require a forecast probability at or above this value.",
    ),
    max_probability: float | None = typer.Option(
        None,
        "--max-probability",
        min=0.0,
        max=1.0,
        help="Require a forecast probability at or below this value.",
    ),
    sort: str = typer.Option(
        ThreatSort.PRIORITY.value,
        "--sort",
        help=(
            "Sort by priority, probability, severity, confidence, last_seen, first_seen, or title."
        ),
    ),
    limit: int = typer.Option(DEFAULT_CLI_LIMIT, "--limit", min=1, max=MAX_CLI_LIMIT),
    summary: bool = typer.Option(False, "--summary", help="Return compact threat summaries."),
    pretty: bool = typer.Option(False, "--pretty", help="Pretty-print JSON output."),
) -> None:
    storage = build_storage(get_settings())
    filters = _build_threat_filters(
        query=query,
        severity=severity,
        status=status,
        cve=cve,
        product=product,
        actor=actor,
        sector=sector,
        campaign=campaign,
        horizon=horizon,
        ai_attack_type=ai_attack_type,
        min_probability=min_probability,
        max_probability=max_probability,
    )
    parsed_sort = _parse_enum(ThreatSort, sort, "sort")
    threats = filter_threats(storage.list_threats(), filters, sort=parsed_sort)
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
            detection for detection in detections if detection.related_threat_id == threat_id
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


@detections_app.command("validate")
def validate_detection(
    detection_id: str,
    telemetry_source: str = typer.Option(
        ...,
        "--telemetry-source",
        help="Telemetry source the rule was validated against (e.g. splunk-lab).",
    ),
    reviewer: str = typer.Option(
        ...,
        "--reviewer",
        help="Reviewer who validated the detection.",
    ),
    sample_size: int = typer.Option(
        ...,
        "--sample-size",
        min=1,
        help="Number of representative samples evaluated.",
    ),
    true_positives: int = typer.Option(
        ...,
        "--true-positives",
        min=0,
        help="True positives observed during validation.",
    ),
    false_positives: int = typer.Option(
        0,
        "--false-positives",
        min=0,
        help="False positives observed during validation.",
    ),
    summary: str = typer.Option(
        ...,
        "--summary",
        help="Short summary or analyst note about the validation evidence.",
    ),
    pretty: bool = typer.Option(False, "--pretty", help="Pretty-print JSON output."),
) -> None:
    """Validate a draft detection with structured evidence."""
    from greynoc_detector_engine.models.detection import (
        ValidationEvidence,
        ValidationResult,
    )
    from greynoc_detector_engine.workers.jobs import (
        DetectionLifecycleError,
        update_detection_status,
    )

    evidence = ValidationEvidence(
        result=ValidationResult.PASSED,
        summary=summary,
        telemetry_source=telemetry_source,
        sample_size=sample_size,
        true_positive_count=true_positives,
        false_positive_count=false_positives,
        reviewer=reviewer,
    )
    storage = build_storage(get_settings())
    try:
        result = update_detection_status(
            storage,
            detection_id,
            DetectionStatus.VALIDATED,
            note=summary,
            evidence=evidence,
        )
    except DetectionLifecycleError as exc:
        raise typer.BadParameter(str(exc)) from exc
    if result.status == "not_found":
        typer.echo(f"Detection not found: {detection_id}", err=True)
        raise typer.Exit(1)
    _emit_json(result.model_dump(mode="json"), pretty=pretty)


@detections_app.command("reject")
def reject_detection(
    detection_id: str,
    reviewer: str = typer.Option(
        ...,
        "--reviewer",
        help="Reviewer rejecting the detection.",
    ),
    reason: str = typer.Option(
        ...,
        "--reason",
        help="Why the detection is being deprecated (required note).",
    ),
    telemetry_source: str | None = typer.Option(
        None,
        "--telemetry-source",
        help="Optional telemetry source consulted while rejecting.",
    ),
    sample_size: int | None = typer.Option(
        None,
        "--sample-size",
        min=0,
        help="Optional sample size consulted while rejecting.",
    ),
    pretty: bool = typer.Option(False, "--pretty", help="Pretty-print JSON output."),
) -> None:
    """Mark a detection as deprecated with a documented reason."""
    from greynoc_detector_engine.models.detection import (
        ValidationEvidence,
        ValidationResult,
    )
    from greynoc_detector_engine.workers.jobs import (
        DetectionLifecycleError,
        update_detection_status,
    )

    evidence = ValidationEvidence(
        result=ValidationResult.FAILED,
        summary=reason,
        reviewer=reviewer,
        telemetry_source=telemetry_source,
        sample_size=sample_size,
    )
    storage = build_storage(get_settings())
    try:
        result = update_detection_status(
            storage,
            detection_id,
            DetectionStatus.DEPRECATED,
            note=reason,
            evidence=evidence,
        )
    except DetectionLifecycleError as exc:
        raise typer.BadParameter(str(exc)) from exc
    if result.status == "not_found":
        typer.echo(f"Detection not found: {detection_id}", err=True)
        raise typer.Exit(1)
    _emit_json(result.model_dump(mode="json"), pretty=pretty)


@detections_app.command("quality")
def detection_quality(
    detection_id: str,
    pretty: bool = typer.Option(False, "--pretty", help="Pretty-print JSON output."),
) -> None:
    """Report the quality passport (grade, trust score, blockers) for a detection."""
    from greynoc_detector_engine.intelligence.quality_passport import (
        build_detection_quality_passport,
    )

    storage = build_storage(get_settings())
    detection = storage.get_detection(detection_id)
    if detection is None:
        typer.echo(f"Detection not found: {detection_id}", err=True)
        raise typer.Exit(1)
    passport = build_detection_quality_passport(detection)
    _emit_json(passport.model_dump(mode="json"), pretty=pretty)


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


def _signer_from_settings() -> HybridSigner | None:
    """Build a signer from the configured shared secret, or None if unset."""
    from greynoc_detector_engine.crypto import HybridSigner, keyset_from_hmac_secret

    secret = get_settings().signing_hmac_key
    if secret is None:
        return None
    return HybridSigner(keyset_from_hmac_secret(secret.get_secret_value()))


@export_app.command("stix")
def export_stix(
    out: Path = typer.Option(..., "--out", help="Path to write the STIX 2.1 bundle JSON."),
    sign: bool = typer.Option(
        False, "--sign", help="Also write a hybrid signature envelope (<out>.sig.json)."
    ),
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
    result: dict[str, object] = {"path": str(out), "objects": len(bundle.objects)}
    if sign:
        signer = _signer_from_settings()
        if signer is None:
            typer.echo(
                "Signing requested but GREYNOC_SIGNING_HMAC_KEY is not configured.", err=True
            )
            raise typer.Exit(1)
        envelope = signer.sign(out.read_bytes())
        sig_path = out.with_name(out.name + ".sig.json")
        sig_path.write_text(envelope.model_dump_json(indent=2), encoding="utf-8")
        result["signature"] = str(sig_path)
        result["algorithms"] = envelope.algorithms
    typer.echo(json.dumps(result))


@app.command("verify-signature")
def verify_signature_command(
    artifact: Path = typer.Argument(..., exists=True, readable=True, help="Signed artifact file."),
    signature: Path = typer.Argument(
        ..., exists=True, readable=True, help="The .sig.json envelope."
    ),
    pretty: bool = typer.Option(False, "--pretty", help="Pretty-print JSON output."),
) -> None:
    """Verify a hybrid signature envelope against an artifact's bytes."""
    from greynoc_detector_engine.crypto import HybridSigner, SignatureEnvelope, SigningKeyset

    signer = _signer_from_settings() or HybridSigner(SigningKeyset())
    envelope = SignatureEnvelope.model_validate_json(signature.read_text(encoding="utf-8"))
    result = signer.verify(artifact.read_bytes(), envelope)
    _emit_json(
        {
            "ok": result.ok,
            "verified": result.verified,
            "unverifiable": result.unverifiable,
            "strongest_algorithm": result.strongest_algorithm,
            "quantum_resistant": result.quantum_resistant,
            "notes": result.notes,
        },
        pretty=pretty,
    )
    raise typer.Exit(0 if result.ok else 2)


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


@doctor_app.command("crypto")
def doctor_crypto() -> None:
    """Report the engine's post-quantum cryptographic posture."""
    from greynoc_detector_engine.workers.health import render_findings, run_crypto_posture_check

    report = run_crypto_posture_check()
    typer.echo(render_findings(report.findings))
    raise typer.Exit(report.exit_code)


def _load_eval_corpus(
    corpus: Path | None, lenient: bool
) -> tuple[list[ForecastExample], ForecastCorpusStats]:
    from greynoc_detector_engine.eval.corpus import DEFAULT_CORPUS, load_forecast_corpus

    path = corpus or DEFAULT_CORPUS
    if not path.exists():
        typer.echo(f"Corpus not found: {path}", err=True)
        raise typer.Exit(1)
    return load_forecast_corpus(path, lenient=lenient)


@eval_app.command("report")
def eval_report(
    corpus: Path | None = typer.Argument(None, help="Corpus JSONL (defaults to bundled seed set)."),
    threshold: float = typer.Option(0.5, "--threshold", min=0.0, max=1.0),
    lenient: bool = typer.Option(False, "--lenient", help="Skip malformed rows."),
    pretty: bool = typer.Option(False, "--pretty", help="Pretty-print JSON output."),
) -> None:
    """Score forecast probabilities against realized outcomes (ROC-AUC, TPR@FPR, F1, ECE)."""
    from greynoc_detector_engine.eval.runner import evaluate_forecast_corpus

    examples, stats = _load_eval_corpus(corpus, lenient)
    report = evaluate_forecast_corpus(examples, threshold=threshold)
    _emit_json({"corpus": stats.as_dict(), "report": report.as_dict()}, pretty=pretty)


@eval_app.command("calibrate")
def eval_calibrate(
    corpus: Path | None = typer.Argument(None, help="Corpus JSONL (defaults to bundled seed set)."),
    l2: float = typer.Option(1.0, "--l2", min=0.0, help="L2 regularization strength."),
    lenient: bool = typer.Option(False, "--lenient", help="Skip malformed rows."),
    pretty: bool = typer.Option(False, "--pretty", help="Pretty-print JSON output."),
) -> None:
    """Fit Platt scaling so the fused score reads as a probability; report ECE/Brier."""
    from greynoc_detector_engine.eval.runner import fit_forecast_calibration

    examples, stats = _load_eval_corpus(corpus, lenient)
    result = fit_forecast_calibration(examples, l2=l2)
    _emit_json({"corpus": stats.as_dict(), "calibration": result.as_dict()}, pretty=pretty)


@eval_app.command("learn-weights")
def eval_learn_weights(
    corpus: Path | None = typer.Argument(None, help="Corpus JSONL (defaults to bundled seed set)."),
    l2: float = typer.Option(2.0, "--l2", min=0.0, help="L2 regularization strength."),
    out: Path | None = typer.Option(None, "--out", help="Write learned weights JSON to a file."),
    lenient: bool = typer.Option(False, "--lenient", help="Skip malformed rows."),
    pretty: bool = typer.Option(False, "--pretty", help="Pretty-print JSON output."),
) -> None:
    """Learn glass-box per-driver predictive_fusion_weights from realized outcomes."""
    from greynoc_detector_engine.eval.runner import learn_fusion_weights

    examples, _ = _load_eval_corpus(corpus, lenient)
    learned = learn_fusion_weights(examples, l2=l2).as_dict()
    if out is not None:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(learned, indent=2), encoding="utf-8")
        typer.echo(json.dumps({"path": str(out), "trained_on": learned["trained_on"]}))
        return
    _emit_json(learned, pretty=pretty)


@quantum_app.command("scan")
def quantum_scan(
    text: str = typer.Argument(..., help="Threat text / advisory to assess for quantum exposure."),
    product: list[str] | None = typer.Option(None, "--product", help="Affected product (repeat)."),
    pretty: bool = typer.Option(False, "--pretty", help="Pretty-print JSON output."),
) -> None:
    """Assess text for quantum-vulnerable crypto and harvest-now-decrypt-later risk."""
    from greynoc_detector_engine.analysis.quantum_risk import QuantumRiskClassifier

    assessment = QuantumRiskClassifier().assess(text, list(product or []))
    _emit_json(assessment.model_dump(mode="json"), pretty=pretty)


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
        with record_job(storage, f"ingest:{source}") as summary:
            result = run_ingest_job(
                source=source,
                settings=settings,
                storage=storage,
                fixture_path=fixture,
            )
            summary.update(result.counts)
            summary["status"] = result.status
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


def _build_threat_filters(
    *,
    query: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    cve: str | None = None,
    product: str | None = None,
    actor: str | None = None,
    sector: str | None = None,
    campaign: str | None = None,
    horizon: str | None = None,
    ai_attack_type: str | None = None,
    min_probability: float | None = None,
    max_probability: float | None = None,
) -> ThreatQueryFilters:
    if (
        min_probability is not None
        and max_probability is not None
        and min_probability > max_probability
    ):
        raise typer.BadParameter("min_probability cannot be greater than max_probability")
    return ThreatQueryFilters(
        query=query,
        severity=_parse_enum(ThreatSeverity, severity, "severity") if severity else None,
        status=_parse_enum(ThreatStatus, status, "status") if status else None,
        cve=cve.upper() if cve else None,
        product=product,
        actor=actor,
        sector=sector,
        campaign=campaign,
        horizon=_parse_enum(ForecastHorizon, horizon, "horizon") if horizon else None,
        ai_attack_type=(
            _parse_enum(AIAttackType, ai_attack_type, "ai_attack_type") if ai_attack_type else None
        ),
        min_probability=min_probability,
        max_probability=max_probability,
    )


def _threat_summary(threat: ThreatRecord) -> dict[str, Any]:
    return summarize_threat(threat)


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


def _keystore() -> Any:
    from greynoc_detector_engine.crypto.keystore import Keystore

    return Keystore(get_settings().keystore_path)


@crypto_app.command("algorithms")
def crypto_algorithms(
    family: str | None = typer.Option(None, "--family", help="Filter: kem, signature, hash, ..."),
    cnsa: bool = typer.Option(False, "--cnsa", help="Only the CNSA 2.0 suite."),
    vulnerable: bool = typer.Option(False, "--vulnerable", help="Only quantum-vulnerable."),
    pretty: bool = typer.Option(False, "--pretty", help="Pretty-print JSON output."),
) -> None:
    """List the post-quantum algorithm registry (sizes, categories, standards, deadlines)."""
    from greynoc_detector_engine.crypto import algorithms as alg

    records = alg.all_algorithms()
    if family is not None:
        records = tuple(r for r in records if r.family.value == family.strip().lower())
    if cnsa:
        records = tuple(r for r in records if r.cnsa_2_0)
    if vulnerable:
        records = tuple(r for r in records if r.quantum_vulnerable)
    payload = [
        {
            "name": r.name,
            "family": r.family.value,
            "standard": r.standard.value if r.standard is not None else None,
            "quantum_threat": r.quantum_threat.value,
            "quantum_safe": r.quantum_safe,
            "nist_category": r.nist_category,
            "classical_bits": r.classical_bits,
            "cnsa_2_0": r.cnsa_2_0,
            "deprecated_after": r.deprecated_after,
            "disallowed_after": r.disallowed_after,
            "replaces_with": list(r.replaces_with),
        }
        for r in records
    ]
    _emit_json(payload, pretty=pretty)


@crypto_app.command("posture")
def crypto_posture_command(
    pretty: bool = typer.Option(False, "--pretty", help="Pretty-print JSON output."),
) -> None:
    """Machine-readable post-quantum posture (see also: gn doctor crypto)."""
    from greynoc_detector_engine.crypto import crypto_posture

    posture = crypto_posture()
    payload = posture.model_dump(mode="json")
    payload["ready"] = posture.ready
    _emit_json(payload, pretty=pretty)


@crypto_app.command("selftest")
def crypto_selftest_command(
    pretty: bool = typer.Option(False, "--pretty", help="Pretty-print JSON output."),
) -> None:
    """Run known-answer / round-trip self-tests for every available crypto backend."""
    from greynoc_detector_engine.crypto.selftest import run_crypto_selftest

    report = run_crypto_selftest()
    _emit_json(report.as_dict(), pretty=pretty)
    raise typer.Exit(0 if report.ok else 2)


@crypto_app.command("keygen")
def crypto_keygen(
    key_id: str = typer.Option(..., "--key-id", help="Identifier for the new key."),
    algo: list[str] | None = typer.Option(
        None, "--algo", help="Backends: hmac, lms, ed25519, mldsa (repeat). Default: hmac + lms."
    ),
    pretty: bool = typer.Option(False, "--pretty", help="Pretty-print JSON output."),
) -> None:
    """Generate a managed signing key (default: HMAC + always-available post-quantum LMS)."""
    from greynoc_detector_engine.crypto.keystore import KeystoreError

    try:
        meta = _keystore().generate_key(key_id, algorithms=list(algo) if algo else None)
    except KeystoreError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1) from exc
    _emit_json(meta.model_dump(mode="json"), pretty=pretty)


@crypto_app.command("keys")
def crypto_keys(
    pretty: bool = typer.Option(False, "--pretty", help="Pretty-print JSON output."),
) -> None:
    """List managed keys (metadata only -- never secret material)."""
    keys = _keystore().list_keys()
    _emit_json([m.model_dump(mode="json") for m in keys], pretty=pretty)


@crypto_app.command("rotate")
def crypto_rotate(
    old: str = typer.Option(..., "--old", help="Key id to retire."),
    new: str = typer.Option(..., "--new", help="New key id."),
    pretty: bool = typer.Option(False, "--pretty", help="Pretty-print JSON output."),
) -> None:
    """Rotate a signing key: generate a successor and retire the old one."""
    from greynoc_detector_engine.crypto.keystore import KeystoreError

    try:
        meta = _keystore().rotate_key(old, new)
    except KeystoreError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1) from exc
    _emit_json(meta.model_dump(mode="json"), pretty=pretty)


@crypto_app.command("sign")
def crypto_sign(
    artifact: Path = typer.Argument(..., exists=True, readable=True, help="File to sign."),
    key_id: str = typer.Option(..., "--key-id", help="Keystore key to sign with."),
    out: Path | None = typer.Option(None, "--out", help="Default <artifact>.sig.json."),
    pretty: bool = typer.Option(False, "--pretty", help="Pretty-print JSON output."),
) -> None:
    """Sign an artifact with a managed key (advances + persists stateful LMS state)."""
    from greynoc_detector_engine.crypto.keystore import KeystoreError

    try:
        envelope = _keystore().sign_artifact(key_id, artifact.read_bytes())
    except KeystoreError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1) from exc
    sig_path = out or artifact.with_name(artifact.name + ".sig.json")
    sig_path.write_text(envelope.model_dump_json(indent=2), encoding="utf-8")
    _emit_json(
        {
            "artifact": str(artifact),
            "signature": str(sig_path),
            "algorithms": envelope.algorithms,
            "quantum_resistant": envelope.quantum_resistant,
        },
        pretty=pretty,
    )


@crypto_app.command("kem-keygen")
def crypto_kem_keygen(
    out: Path = typer.Option(..., "--out", help="Path to write the KEM keypair JSON (SECRET)."),
    pretty: bool = typer.Option(False, "--pretty", help="Pretty-print JSON output."),
) -> None:
    """Generate a hybrid X25519 (+ ML-KEM) keypair for artifact encryption."""
    from greynoc_detector_engine.crypto import kem

    try:
        keypair = kem.generate_kem_keypair()
    except RuntimeError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1) from exc
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(keypair.to_dict(), indent=2), encoding="utf-8")
    _emit_json({"keypair": str(out), "quantum_safe": kem.mlkem_available()}, pretty=pretty)


@crypto_app.command("encrypt")
def crypto_encrypt(
    source: Path = typer.Argument(..., exists=True, readable=True, help="File to encrypt."),
    key: Path = typer.Option(..., "--key", exists=True, help="Recipient KEM keypair/bundle JSON."),
    out: Path = typer.Option(..., "--out", help="Path to write the KEM envelope JSON."),
    pretty: bool = typer.Option(False, "--pretty", help="Pretty-print JSON output."),
) -> None:
    """Encrypt a file to a recipient with the hybrid KEM (AES-256-GCM AEAD)."""
    from greynoc_detector_engine.crypto import kem

    keypair = kem.HybridKemKeypair.from_dict(json.loads(key.read_text(encoding="utf-8")))
    envelope = kem.encrypt(source.read_bytes(), keypair.public_bundle())
    out.write_text(envelope.model_dump_json(indent=2), encoding="utf-8")
    _emit_json(
        {"out": str(out), "algorithms": envelope.algorithms, "quantum_safe": envelope.quantum_safe},
        pretty=pretty,
    )


@crypto_app.command("decrypt")
def crypto_decrypt(
    envelope: Path = typer.Argument(..., exists=True, readable=True, help="KEM envelope JSON."),
    key: Path = typer.Option(..., "--key", exists=True, help="Recipient KEM keypair JSON."),
    out: Path = typer.Option(..., "--out", help="Path to write the decrypted plaintext."),
) -> None:
    """Decrypt a KEM envelope with the recipient keypair."""
    from greynoc_detector_engine.crypto import kem

    keypair = kem.HybridKemKeypair.from_dict(json.loads(key.read_text(encoding="utf-8")))
    env = kem.KemEnvelope.model_validate_json(envelope.read_text(encoding="utf-8"))
    out.write_bytes(kem.decrypt(env, keypair))
    typer.echo(json.dumps({"out": str(out)}))


@crypto_app.command("cbom")
def crypto_cbom(
    inventory: Path = typer.Option(..., "--inventory", exists=True, help="Inventory YAML/JSON."),
    out: Path | None = typer.Option(None, "--out", help="Path to write the CBOM JSON."),
) -> None:
    """Emit a CycloneDX 1.6 Cryptographic Bill of Materials from an inventory."""
    from greynoc_detector_engine.analysis import cbom as cbom_mod
    from greynoc_detector_engine.analysis import crypto_inventory as ci

    assets, _summary, _mosca = ci.assess_inventory(ci.load_inventory(inventory))
    bom = cbom_mod.generate_cbom(assets)
    text = cbom_mod.to_json(bom)
    if out is not None:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        typer.echo(json.dumps({"out": str(out), "components": len(assets)}))
        return
    typer.echo(text)


@crypto_log_app.command("append")
def crypto_log_append(
    name: str = typer.Argument(..., help="Artifact name/label."),
    artifact: Path = typer.Argument(..., exists=True, readable=True, help="Artifact file."),
    pretty: bool = typer.Option(False, "--pretty", help="Pretty-print JSON output."),
) -> None:
    """Append an artifact to the tamper-evident transparency log."""
    from greynoc_detector_engine.crypto.transparency import TransparencyLog

    log = TransparencyLog(get_settings().transparency_log_path)
    entry = log.append(name, artifact.read_bytes())
    _emit_json(entry.model_dump(mode="json"), pretty=pretty)


@crypto_log_app.command("root")
def crypto_log_root(
    pretty: bool = typer.Option(False, "--pretty", help="Pretty-print JSON output."),
) -> None:
    """Show the current Merkle tree size and root hash."""
    from greynoc_detector_engine.crypto.transparency import TransparencyLog

    log = TransparencyLog(get_settings().transparency_log_path)
    _emit_json({"size": log.size(), "root": log.root()}, pretty=pretty)


@crypto_log_app.command("checkpoint")
def crypto_log_checkpoint(
    key_id: str | None = typer.Option(
        None, "--key-id", help="Keystore key that signs the checkpoint (default: configured)."
    ),
    out: Path | None = typer.Option(None, "--out", help="Checkpoint output path."),
    pretty: bool = typer.Option(False, "--pretty", help="Pretty-print JSON output."),
) -> None:
    """Produce a post-quantum-signed checkpoint (signed tree head) of the log.

    The checkpoint is signed with a *persistent, pinnable* keystore key (created
    on first use), not a throwaway key, so the log has a stable well-known public
    key. Publish the returned ``public_key`` once; verifiers pin it with
    ``verify-checkpoint --pubkey`` to reject forged checkpoints. The keystore
    advances and durably persists the stateful LMS/HSS state per signature.
    """
    from greynoc_detector_engine.crypto.keystore import KeystoreError
    from greynoc_detector_engine.crypto.transparency import TransparencyLog

    settings = get_settings()
    resolved_key_id = key_id or settings.transparency_log_key_id
    keystore = _keystore()
    try:
        meta = keystore.get_metadata(resolved_key_id)
    except KeystoreError:
        # First checkpoint: mint a pure-PQ (LMS/HSS) log key so any holder of the
        # public key can verify without a shared secret.
        meta = keystore.generate_key(resolved_key_id, algorithms=["lms"])

    log = TransparencyLog(settings.transparency_log_path)
    try:
        checkpoint = log.build_checkpoint(
            lambda payload: keystore.sign_artifact(resolved_key_id, payload)
        )
    except KeystoreError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1) from exc
    text = checkpoint.model_dump_json(indent=2)
    if out is not None:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
    _emit_json(
        {
            "tree_size": checkpoint.tree_size,
            "root": checkpoint.root_hash,
            "key_id": resolved_key_id,
            "public_key": meta.public_key,
            "out": str(out) if out else None,
        },
        pretty=pretty,
    )


@crypto_log_app.command("verify-checkpoint")
def crypto_log_verify_checkpoint(
    checkpoint: Path = typer.Argument(..., exists=True, readable=True, help="Checkpoint JSON."),
    pubkey: str | None = typer.Option(
        None, "--pubkey", help="Base64 LMS public key to pin (the log's published key)."
    ),
    key_id: str | None = typer.Option(
        None, "--key-id", help="Pin to a local keystore key's public key instead of --pubkey."
    ),
    pretty: bool = typer.Option(False, "--pretty", help="Pretty-print JSON output."),
) -> None:
    """Verify a checkpoint's PQ signature and that its root matches the live log.

    Authenticity requires pinning the log's public key: pass ``--pubkey`` (the
    published key) or ``--key-id`` (a local keystore key). With neither, the
    configured log key is used if present locally; otherwise the signature is only
    self-attesting (any key verifies), ``authenticated`` is ``false``, and a
    warning is emitted. Exit code is non-zero unless the signature verifies *and*
    the checkpoint root matches the live log.
    """
    from greynoc_detector_engine.crypto.keystore import KeystoreError
    from greynoc_detector_engine.crypto.signing import ALG_LMS, HybridSigner, SigningKeyset
    from greynoc_detector_engine.crypto.transparency import (
        SignedCheckpoint,
        TransparencyLog,
        checkpoint_public_keys,
    )

    settings = get_settings()
    cp = SignedCheckpoint.model_validate_json(checkpoint.read_text(encoding="utf-8"))

    pin = pubkey
    pin_source = "pubkey" if pubkey else None
    if pin is None and key_id is not None:
        try:
            pin = _keystore().get_metadata(key_id).public_key
            pin_source = f"keystore:{key_id}"
        except KeystoreError as exc:
            typer.echo(str(exc), err=True)
            raise typer.Exit(1) from exc
    if pin is None and key_id is None and pubkey is None:
        # Best-effort: pin the configured log key when this host holds the keystore.
        try:
            pin = _keystore().get_metadata(settings.transparency_log_key_id).public_key
            if pin is not None:
                pin_source = f"keystore:{settings.transparency_log_key_id}"
        except KeystoreError:
            pin = None

    expected = {ALG_LMS: pin} if pin else None
    signature_ok = TransparencyLog.verify_checkpoint(
        cp, HybridSigner(SigningKeyset()), expected_public_keys=expected
    )
    log = TransparencyLog(settings.transparency_log_path)
    root_matches = cp.root_hash == log.root() and cp.tree_size == log.size()
    notes: list[str] = []
    if pin is None:
        notes.append(
            "no public key pinned (--pubkey/--key-id); signature is self-attesting, "
            "not authenticated"
        )
    _emit_json(
        {
            "signature_ok": signature_ok,
            "authenticated": bool(pin) and signature_ok,
            "root_matches_live_log": root_matches,
            "pin_source": pin_source,
            "pinned_key": pin,
            "signing_key": checkpoint_public_keys(cp).get(ALG_LMS),
            "checkpoint_root": cp.root_hash,
            "live_root": log.root(),
            "notes": notes,
        },
        pretty=pretty,
    )
    raise typer.Exit(0 if (signature_ok and root_matches) else 2)


@quantum_app.command("inventory")
def quantum_inventory(
    path: Path = typer.Argument(..., exists=True, readable=True, help="Inventory YAML/JSON."),
    pretty: bool = typer.Option(False, "--pretty", help="Pretty-print JSON output."),
) -> None:
    """Assess a crypto inventory's quantum posture (per-asset Mosca + summary)."""
    from greynoc_detector_engine.analysis import crypto_inventory as ci

    settings = get_settings()
    entries = ci.load_inventory(path)
    assets, summary, mosca = ci.assess_inventory(
        entries,
        crqc_years=settings.crqc_estimate_years,
        default_shelf_life_years=settings.default_data_shelf_life_years,
        default_migration_years=settings.default_migration_years,
    )
    _emit_json(
        {
            "summary": summary.model_dump(mode="json"),
            "assets": [a.model_dump(mode="json") for a in assets],
            "mosca": {k: v.model_dump(mode="json") for k, v in mosca.items()},
        },
        pretty=pretty,
    )


@quantum_app.command("plan")
def quantum_plan(
    path: Path = typer.Argument(..., exists=True, readable=True, help="Inventory YAML/JSON."),
    year: int = typer.Option(2026, "--year", help="Current year for deadline urgency."),
    pretty: bool = typer.Option(False, "--pretty", help="Pretty-print JSON output."),
) -> None:
    """Produce a prioritized CNSA-2.0 / NIST-IR-8547 migration plan for an inventory."""
    from greynoc_detector_engine.analysis import crypto_inventory as ci
    from greynoc_detector_engine.analysis import pqc_migration as pm

    settings = get_settings()
    assets, _summary, _mosca = ci.assess_inventory(
        ci.load_inventory(path),
        crqc_years=settings.crqc_estimate_years,
        default_shelf_life_years=settings.default_data_shelf_life_years,
        default_migration_years=settings.default_migration_years,
    )
    plan = pm.plan_migration(
        assets,
        crqc_years=settings.crqc_estimate_years,
        default_shelf_life_years=settings.default_data_shelf_life_years,
        default_migration_years=settings.default_migration_years,
        current_year=year,
    )
    _emit_json(plan.model_dump(mode="json"), pretty=pretty)


@quantum_app.command("mosca")
def quantum_mosca(
    shelf_life: float = typer.Option(..., "--shelf-life", help="X: data shelf-life (years)."),
    migration: float = typer.Option(..., "--migration", help="Y: migration time (years)."),
    crqc: float = typer.Option(..., "--crqc", help="Z: years until a CRQC exists."),
    pretty: bool = typer.Option(False, "--pretty", help="Pretty-print JSON output."),
) -> None:
    """Evaluate Mosca's inequality (X + Y >= Z => already at risk)."""
    from greynoc_detector_engine.analysis.mosca import assess_mosca

    result = assess_mosca(
        data_shelf_life_years=shelf_life, migration_years=migration, crqc_years=crqc
    )
    _emit_json(result.model_dump(mode="json"), pretty=pretty)


@quantum_app.command("cert")
def quantum_cert(
    path: Path = typer.Argument(..., exists=True, readable=True, help="X.509 cert (PEM or DER)."),
    pretty: bool = typer.Option(False, "--pretty", help="Pretty-print JSON output."),
) -> None:
    """Classify an X.509 certificate's quantum exposure (offline parse)."""
    from greynoc_detector_engine.analysis.tls_posture import analyze_certificate

    asset = analyze_certificate(path.read_bytes())
    _emit_json(asset.model_dump(mode="json"), pretty=pretty)


@quantum_app.command("eval")
def quantum_eval(
    corpus: Path | None = typer.Argument(None, help="Quantum corpus JSONL (defaults to bundled)."),
    pretty: bool = typer.Option(False, "--pretty", help="Pretty-print JSON output."),
) -> None:
    """Score the quantum-risk classifier against a labeled advisory corpus."""
    from greynoc_detector_engine.eval.quantum import (
        DEFAULT_CORPUS,
        evaluate_quantum_corpus,
        load_quantum_corpus,
    )

    examples, stats = load_quantum_corpus(corpus or DEFAULT_CORPUS)
    report = evaluate_quantum_corpus(examples)
    _emit_json({"corpus": stats.as_dict(), "report": report.as_dict()}, pretty=pretty)


@quantum_app.command("timeline")
def quantum_timeline(
    pretty: bool = typer.Option(False, "--pretty", help="Pretty-print JSON output."),
) -> None:
    """Show the CNSA 2.0 + NIST IR 8547 migration timeline and CNSA suite."""
    from greynoc_detector_engine.crypto import algorithms as alg

    _emit_json(
        {
            "nsm10_endpoint_year": alg.NSM10_ENDPOINT_YEAR,
            "cnsa_2_0_exclusive_year": alg.CNSA_2_0_EXCLUSIVE_YEAR,
            "cnsa_2_0_acquisition_gate_year": alg.CNSA_2_0_ACQUISITION_GATE_YEAR,
            "cnsa_2_0_timeline": alg.CNSA_2_0_TIMELINE,
            "cnsa_2_0_suite": [r.name for r in alg.cnsa_2_0_suite()],
        },
        pretty=pretty,
    )


if __name__ == "__main__":
    app()
