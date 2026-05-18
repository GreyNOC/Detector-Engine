from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from greynoc_detector_engine.api.dependencies import get_storage, require_api_key
from greynoc_detector_engine.storage.sqlite import SQLiteStorage
from greynoc_detector_engine.workers.jobs import generate_detections_for_threat

router = APIRouter()


@router.get("/detections")
def list_detections(storage: SQLiteStorage = Depends(get_storage)) -> list[dict[str, object]]:
    return [record.model_dump(mode="json") for record in storage.list_detections()]


@router.get("/detections/{detection_id}")
def get_detection(
    detection_id: str,
    storage: SQLiteStorage = Depends(get_storage),
) -> dict[str, object]:
    record = storage.get_detection(detection_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Detection not found")
    return record.model_dump(mode="json")


@router.post("/detections/generate/{threat_id}", dependencies=[Depends(require_api_key)])
def generate_detections(
    threat_id: str,
    storage: SQLiteStorage = Depends(get_storage),
) -> dict[str, object]:
    result = generate_detections_for_threat(storage, threat_id)
    if result.status == "not_found":
        raise HTTPException(status_code=404, detail="Threat not found")
    return result.model_dump(mode="json")
