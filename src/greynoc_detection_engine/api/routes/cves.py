from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from greynoc_detection_engine.api.dependencies import get_storage
from greynoc_detection_engine.catalog.storage import SQLiteStorage

router = APIRouter()


@router.get("/cves")
def list_cves(storage: SQLiteStorage = Depends(get_storage)) -> list[dict[str, object]]:
    return [record.model_dump(mode="json") for record in storage.list_cves()]


@router.get("/cves/{cve_id}")
def get_cve(cve_id: str, storage: SQLiteStorage = Depends(get_storage)) -> dict[str, object]:
    record = storage.get_cve(cve_id.upper())
    if record is None:
        raise HTTPException(status_code=404, detail="CVE not found")
    return record.model_dump(mode="json")
