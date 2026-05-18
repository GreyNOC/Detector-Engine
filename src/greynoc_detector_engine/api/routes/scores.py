from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from greynoc_detector_engine.api.dependencies import get_storage
from greynoc_detector_engine.storage.sqlite import SQLiteStorage

router = APIRouter()


@router.get("/scores/events")
def list_score_events(
    target_id: str | None = Query(default=None),
    score_type: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    storage: SQLiteStorage = Depends(get_storage),
) -> dict[str, object]:
    events = storage.list_score_events(
        target_id=target_id,
        score_type=score_type,
        limit=limit,
    )
    return {
        "count": len(events),
        "events": [event.model_dump(mode="json") for event in events],
    }
