from __future__ import annotations

from fastapi import APIRouter, Depends

from greynoc_detector_engine.api.dependencies import get_storage
from greynoc_detector_engine.api.pagination import LimitParam, apply_limit
from greynoc_detector_engine.storage.sqlite import SQLiteStorage

router = APIRouter()


@router.get("/kev")
def list_kev(
    limit: LimitParam,
    storage: SQLiteStorage = Depends(get_storage),
) -> list[dict[str, object]]:
    return [record.model_dump(mode="json") for record in apply_limit(storage.list_kev(), limit)]
