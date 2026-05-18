"""Repeatable end-to-end demo / golden-path workflow.

Runs the standard defensive operator sequence against locally available
fixtures so a new operator can exercise the engine without network access.
The demo never fetches live sources unless the caller opts in.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from greynoc_detector_engine.config.settings import Settings
from greynoc_detector_engine.storage.sqlite import SQLiteStorage
from greynoc_detector_engine.workers.jobs import (
    IngestSourceName,
    build_storage,
    generate_detections_for_all,
    initialize_project,
    run_correlation_job,
    run_ingest_job,
    run_predict_job,
)

# Sources we attempt to load during the demo, in operator-friendly order.
# Each entry maps to a fixture file under ``settings.fixture_root``.
DEMO_SOURCES: tuple[tuple[IngestSourceName, str], ...] = (
    ("cve", "cve_sample.json"),
    ("kev", "kev_sample.json"),
    ("epss", "epss_sample.json"),
    ("rss", "rss_sample.xml"),
    ("threatfox", "threatfox_sample.json"),
    ("urlhaus", "urlhaus_sample.json"),
    ("ransomwatch", "ransomwatch_sample.json"),
)


class WorkflowStepResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    step: str
    status: Literal["ok", "skipped", "failed"]
    counts: dict[str, int] = Field(default_factory=dict)
    message: str | None = None


class WorkflowDemoReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["ok", "partial", "failed"]
    steps: list[WorkflowStepResult] = Field(default_factory=list)
    counts: dict[str, int] = Field(default_factory=dict)


def run_workflow_demo(
    settings: Settings,
    *,
    storage: SQLiteStorage | None = None,
    fixture_root: Path | None = None,
    generate_detections: bool = True,
) -> WorkflowDemoReport:
    """Run the local golden-path demo and return a compact report.

    The workflow:
      1. ensures local project/data directories exist,
      2. ingests fixture-backed sources that are present on disk,
      3. correlates weak signals into threat records,
      4. runs the predictive layer,
      5. optionally generates draft detections for all threats,
      6. returns a compact JSON-friendly summary.
    """

    storage = storage or build_storage(settings)
    fixture_root = (fixture_root or settings.fixture_root).resolve()

    steps: list[WorkflowStepResult] = []
    failures = 0

    init_result = initialize_project(settings)
    steps.append(
        WorkflowStepResult(
            step="init",
            status="ok",
            counts=dict(init_result.counts),
        )
    )

    for source, fixture_name in DEMO_SOURCES:
        fixture_path = fixture_root / fixture_name
        if not fixture_path.exists():
            steps.append(
                WorkflowStepResult(
                    step=f"ingest:{source}",
                    status="skipped",
                    message=f"Fixture not found: {fixture_path}",
                )
            )
            continue
        try:
            ingest_result = run_ingest_job(
                source=source,
                settings=settings,
                storage=storage,
                fixture_path=fixture_path,
            )
            steps.append(
                WorkflowStepResult(
                    step=f"ingest:{source}",
                    status="ok" if ingest_result.status == "ok" else "skipped",
                    counts=dict(ingest_result.counts),
                    message=(ingest_result.messages[-1] if ingest_result.messages else None),
                )
            )
        except Exception as exc:
            failures += 1
            steps.append(
                WorkflowStepResult(
                    step=f"ingest:{source}",
                    status="failed",
                    message=str(exc),
                )
            )

    try:
        correlation_result = run_correlation_job(storage)
        steps.append(
            WorkflowStepResult(
                step="correlate",
                status="ok",
                counts=dict(correlation_result.counts),
            )
        )
    except Exception as exc:
        failures += 1
        steps.append(WorkflowStepResult(step="correlate", status="failed", message=str(exc)))

    try:
        predict_result = run_predict_job(storage)
        steps.append(
            WorkflowStepResult(
                step="predict",
                status="ok",
                counts=dict(predict_result.counts),
            )
        )
    except Exception as exc:
        failures += 1
        steps.append(WorkflowStepResult(step="predict", status="failed", message=str(exc)))

    if generate_detections:
        try:
            detection_result = generate_detections_for_all(storage)
            steps.append(
                WorkflowStepResult(
                    step="generate-detections",
                    status="ok",
                    counts=dict(detection_result.counts),
                )
            )
        except Exception as exc:
            failures += 1
            steps.append(
                WorkflowStepResult(
                    step="generate-detections",
                    status="failed",
                    message=str(exc),
                )
            )

    counts = _collect_summary_counts(storage)

    if failures == 0:
        overall: Literal["ok", "partial", "failed"] = "ok"
    elif counts["threats"] > 0:
        overall = "partial"
    else:
        overall = "failed"

    return WorkflowDemoReport(status=overall, steps=steps, counts=counts)


def _collect_summary_counts(storage: SQLiteStorage) -> dict[str, int]:
    threats = storage.list_threats()
    detections = storage.list_detections()
    forecasts = sum(1 for threat in threats if threat.attack_forecast is not None)
    return {
        "ingest_runs": len(storage.list_source_runs(limit=500)),
        "cves": len(storage.list_cves()),
        "kev_entries": len(storage.list_kev()),
        "raw_items": len(storage.list_raw_items()),
        "threats": len(threats),
        "campaigns": len(storage.list_campaigns()),
        "forecasts": forecasts,
        "draft_detections": len(detections),
    }
