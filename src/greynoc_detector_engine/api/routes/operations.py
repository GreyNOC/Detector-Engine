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
from greynoc_detector_engine.config.settings import Settings
from greynoc_detector_engine.ingest.base import IngestSourceUnavailable
from greynoc_detector_engine.storage.sqlite import SQLiteStorage
from greynoc_detector_engine.workers.jobs import (
    IngestSourceName,
    run_correlation_job,
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
    try:
        result = run_ingest_job(
            source=source,
            settings=settings,
            storage=storage,
            fixture_path=fixture_path,
        )
    except IngestSourceUnavailable as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return result.model_dump(mode="json")


@router.get("/ingest/runs")
def list_ingest_runs(
    limit: int = Query(default=100, ge=1, le=500),
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


@router.post("/correlate/run", dependencies=[Protected])
def run_correlate(storage: SQLiteStorage = Depends(get_storage)) -> dict[str, object]:
    return run_correlation_job(storage).model_dump(mode="json")


@router.post("/correlate", dependencies=[Protected])
def correlate(storage: SQLiteStorage = Depends(get_storage)) -> dict[str, object]:
    return run_correlation_job(storage).model_dump(mode="json")


def _ingest_source(
    source: IngestSourceName,
    fixture_path: Path | None,
    settings: Settings,
    storage: SQLiteStorage,
) -> dict[str, object]:
    try:
        result = run_ingest_job(
            source=source,
            settings=settings,
            storage=storage,
            fixture_path=fixture_path,
        )
    except IngestSourceUnavailable as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return result.model_dump(mode="json")
