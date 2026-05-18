from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from greynoc_detector_engine.api.dependencies import get_storage
from greynoc_detector_engine.api.pagination import LimitQuery, apply_limit
from greynoc_detector_engine.storage.sqlite import SQLiteStorage

router = APIRouter()


@router.get("/threats")
def list_threats(
    limit: Annotated[int, LimitQuery],
    storage: SQLiteStorage = Depends(get_storage),
) -> list[dict[str, object]]:
    return [record.model_dump(mode="json") for record in apply_limit(storage.list_threats(), limit)]


@router.get("/threats/{threat_id}")
def get_threat(threat_id: str, storage: SQLiteStorage = Depends(get_storage)) -> dict[str, object]:
    record = storage.get_threat(threat_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Threat not found")
    return record.model_dump(mode="json")
