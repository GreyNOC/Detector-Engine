from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from greynoc_detector_engine.api.dependencies import get_storage
from greynoc_detector_engine.intelligence.quality_passport import build_detection_quality_passport
from greynoc_detector_engine.intelligence.signal_dna import build_signal_dna
from greynoc_detector_engine.storage.sqlite import SQLiteStorage

router = APIRouter()


@router.get("/intelligence/threats/{threat_id}/signal-dna")
def get_threat_signal_dna(
    threat_id: str,
    storage: SQLiteStorage = Depends(get_storage),
) -> dict[str, object]:
    threat = storage.get_threat(threat_id)
    if threat is None:
        raise HTTPException(status_code=404, detail="Threat not found")
    return build_signal_dna(threat).model_dump(mode="json")


@router.get("/intelligence/detections/{detection_id}/quality-passport")
def get_detection_quality_passport(
    detection_id: str,
    storage: SQLiteStorage = Depends(get_storage),
) -> dict[str, object]:
    detection = storage.get_detection(detection_id)
    if detection is None:
        raise HTTPException(status_code=404, detail="Detection not found")
    return build_detection_quality_passport(detection).model_dump(mode="json")
