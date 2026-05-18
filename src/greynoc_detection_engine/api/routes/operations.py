from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query

from greynoc_detection_engine.api.dependencies import get_app_settings, get_storage
from greynoc_detection_engine.catalog.storage import SQLiteStorage
from greynoc_detection_engine.config.settings import Settings
from greynoc_detection_engine.ingest.base import IngestSourceUnavailable
from greynoc_detection_engine.workers.jobs import (
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
    try:
        result = run_ingest_job(
            source=source,
            settings=settings,
            storage=storage,
            fixture_path=Path(fixture) if fixture else None,
        )
    except IngestSourceUnavailable as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return result.model_dump(mode="json")


@router.post("/correlate/run")
def run_correlate(storage: SQLiteStorage = Depends(get_storage)) -> dict[str, object]:
    return run_correlation_job(storage).model_dump(mode="json")
