from __future__ import annotations

from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query

from greynoc_detector_engine.api.dependencies import (
    get_app_settings,
    get_storage,
    require_api_key,
    resolve_fixture_path,
)
from greynoc_detector_engine.api.job_locks import single_running_job
from greynoc_detector_engine.api.pagination import DEFAULT_LIMIT, LimitParam
from greynoc_detector_engine.config.settings import Settings
from greynoc_detector_engine.ingest.base import IngestSourceUnavailable
from greynoc_detector_engine.storage.sqlite import SQLiteStorage
from greynoc_detector_engine.workers.jobs import (
    IngestSourceName,
    record_job,
    run_correlation_job,
    run_epss_enrichment_job,
    run_ingest_job,
)

router = APIRouter()
Protected = Depends(require_api_key)
FixturePath = Annotated[Path | None, Depends(resolve_fixture_path)]


@router.post("/ingest/run", dependencies=[Protected])
def run_ingest(
    source: IngestSourceName = Query(...),
    fixture_path: FixturePath = None,
    settings: Settings = Depends(get_app_settings),
    storage: SQLiteStorage = Depends(get_storage),
) -> dict[str, object]:
    return _ingest_source(source, fixture_path, settings, storage)


@router.get("/ingest/runs")
def list_ingest_runs(
    limit: LimitParam = DEFAULT_LIMIT,
    storage: SQLiteStorage = Depends(get_storage),
) -> dict[str, object]:
    runs = storage.list_source_runs(limit=limit)
    return {
        "count": len(runs),
        "runs": [run.model_dump(mode="json") for run in runs],
    }


@router.post("/ingest/cve", dependencies=[Protected])
def ingest_cve(
    fixture_path: FixturePath = None,
    settings: Settings = Depends(get_app_settings),
    storage: SQLiteStorage = Depends(get_storage),
) -> dict[str, object]:
    return _ingest_source("cve", fixture_path, settings, storage)


@router.post("/ingest/kev", dependencies=[Protected])
def ingest_kev(
    fixture_path: FixturePath = None,
    settings: Settings = Depends(get_app_settings),
    storage: SQLiteStorage = Depends(get_storage),
) -> dict[str, object]:
    return _ingest_source("kev", fixture_path, settings, storage)


@router.post("/ingest/rss", dependencies=[Protected])
def ingest_rss(
    fixture_path: FixturePath = None,
    settings: Settings = Depends(get_app_settings),
    storage: SQLiteStorage = Depends(get_storage),
) -> dict[str, object]:
    return _ingest_source("rss", fixture_path, settings, storage)


@router.post("/enrich/epss", dependencies=[Protected])
def enrich_epss(
    fixture_path: FixturePath = None,
    settings: Settings = Depends(get_app_settings),
    storage: SQLiteStorage = Depends(get_storage),
) -> dict[str, object]:
    with single_running_job("enrich:epss"), record_job(storage, "enrich:epss") as summary:
        result = run_epss_enrichment_job(
            settings=settings,
            storage=storage,
            fixture_path=fixture_path,
        )
        summary.update(result.counts)
    return result.model_dump(mode="json")


@router.post("/correlate/run", dependencies=[Protected])
def run_correlate(storage: SQLiteStorage = Depends(get_storage)) -> dict[str, object]:
    return _run_correlation(storage)


@router.post("/correlate", dependencies=[Protected])
def correlate(storage: SQLiteStorage = Depends(get_storage)) -> dict[str, object]:
    return _run_correlation(storage)


def _run_correlation(storage: SQLiteStorage) -> dict[str, object]:
    with single_running_job("correlate"), record_job(storage, "correlate") as summary:
        result = run_correlation_job(storage)
        summary.update(result.counts)
    return result.model_dump(mode="json")


def _ingest_source(
    source: IngestSourceName,
    fixture_path: Path | None,
    settings: Settings,
    storage: SQLiteStorage,
) -> dict[str, object]:
    job_type = f"ingest:{source}"
    try:
        with single_running_job(job_type), record_job(storage, job_type) as summary:
            result = run_ingest_job(
                source=source,
                settings=settings,
                storage=storage,
                fixture_path=fixture_path,
            )
            summary.update(result.counts)
            summary["status"] = result.status
    except IngestSourceUnavailable as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return result.model_dump(mode="json")
