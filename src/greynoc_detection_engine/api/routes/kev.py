from __future__ import annotations

from fastapi import APIRouter, Depends

from greynoc_detection_engine.api.dependencies import get_storage
from greynoc_detection_engine.catalog.storage import SQLiteStorage

router = APIRouter()


@router.get("/kev")
def list_kev(storage: SQLiteStorage = Depends(get_storage)) -> list[dict[str, object]]:
    return [record.model_dump(mode="json") for record in storage.list_kev()]
