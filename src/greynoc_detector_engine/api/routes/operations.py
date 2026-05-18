from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from greynoc_detector_engine.api.dependencies import get_app_settings, get_storage
from greynoc_detector_engine.api.safety import validate_fixture_path
from greynoc_detector_engine.config.settings import Settings
from greynoc_detector_engine.ingest.base import IngestSourceUnavailable
from greynoc_detector_engine.storage.sqlite import SQLiteStorage
from greynoc_detector_engine.workers.jobs import (
    IngestSourceName,
    run_correlation_job,
    run_ingest_job,
)

router = APIRouter()


@router.post("/ingest/run")
def run_ingest(
    source: IngestSourceName = Query(...),
    fixture: str | None = Query(default=None),
    settings: Settings = Depends(get_app_settings),
    storage: SQLiteStorage = Depends(get_storage),
) -> dict[str, object]:
    fixture_path = validate_fixture_path(fixture, settings)
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


@router.post("/ingest/cve")
def ingest_cve(
    fixture: str | None = Query(default=None),
    settings: Settings = Depends(get_app_settings),
    storage: SQLiteStorage = Depends(get_storage),
) -> dict[str, object]:
    return _ingest_source("cve", fixture, settings, storage)


@router.post("/ingest/kev")
def ingest_kev(
    fixture: str | None = Query(default=None),
    settings: Settings = Depends(get_app_settings),
    storage: SQLiteStorage = Depends(get_storage),
) -> dict[str, object]:
    return _ingest_source("kev", fixture, settings, storage)


@router.post("/ingest/rss")
def ingest_rss(
    fixture: str | None = Query(default=None),
    settings: Settings = Depends(get_app_settings),
    storage: SQLiteStorage = Depends(get_storage),
) -> dict[str, object]:
    return _ingest_source("rss", fixture, settings, storage)


@router.post("/correlate/run")
def run_correlate(storage: SQLiteStorage = Depends(get_storage)) -> dict[str, object]:
    return run_correlation_job(storage).model_dump(mode="json")


@router.post("/correlate")
def correlate(storage: SQLiteStorage = Depends(get_storage)) -> dict[str, object]:
    return run_correlation_job(storage).model_dump(mode="json")


def _ingest_source(
    source: IngestSourceName,
    fixture: str | None,
    settings: Settings,
    storage: SQLiteStorage,
) -> dict[str, object]:
    fixture_path = validate_fixture_path(fixture, settings)
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
