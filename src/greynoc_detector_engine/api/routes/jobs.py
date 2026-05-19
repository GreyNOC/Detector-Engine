from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from greynoc_detector_engine.api.dependencies import get_storage
from greynoc_detector_engine.api.pagination import DEFAULT_LIMIT, LimitParam
from greynoc_detector_engine.storage.sqlite import SQLiteStorage

router = APIRouter()


@router.get("/jobs")
def list_jobs(
    limit: LimitParam = DEFAULT_LIMIT,
    job_type: str | None = Query(default=None, max_length=120),
    storage: SQLiteStorage = Depends(get_storage),
) -> list[dict[str, object]]:
    entries = storage.list_job_history(job_type=job_type, limit=limit)
    return [entry.model_dump(mode="json") for entry in entries]


@router.get("/jobs/{job_id}")
def get_job(
    job_id: str,
    storage: SQLiteStorage = Depends(get_storage),
) -> dict[str, object]:
    entry = storage.get_job_history(job_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return entry.model_dump(mode="json")
