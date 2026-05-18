from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from greynoc_detector_engine.api.dependencies import get_storage, require_api_key
from greynoc_detector_engine.api.job_locks import single_running_job
from greynoc_detector_engine.api.pagination import LimitQuery, apply_limit
from greynoc_detector_engine.models.detection import (
    DetectionKind,
    DetectionStatus,
    ValidationEvidence,
)
from greynoc_detector_engine.storage.sqlite import SQLiteStorage
from greynoc_detector_engine.workers.jobs import (
    DetectionLifecycleError,
    generate_detections_for_threat,
    update_detection_status,
)

router = APIRouter()


class DetectionStatusUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: DetectionStatus
    note: str | None = Field(default=None, max_length=1000)
    evidence: ValidationEvidence | None = None


@router.get("/detections")
def list_detections(
    limit: Annotated[int, LimitQuery],
    status: DetectionStatus | None = Query(default=None),
    kind: DetectionKind | None = Query(default=None),
    threat_id: str | None = Query(default=None),
    storage: SQLiteStorage = Depends(get_storage),
) -> list[dict[str, object]]:
    records = storage.list_detections()
    if status is not None:
        records = [record for record in records if record.status == status]
    if kind is not None:
        records = [record for record in records if record.kind == kind]
    if threat_id is not None:
        records = [record for record in records if record.related_threat_id == threat_id]
    return [record.model_dump(mode="json") for record in apply_limit(records, limit)]


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
    with single_running_job(f"detections:generate:{threat_id}"):
        result = generate_detections_for_threat(storage, threat_id)
    if result.status == "not_found":
        raise HTTPException(status_code=404, detail="Threat not found")
    return result.model_dump(mode="json")


@router.patch("/detections/{detection_id}/status", dependencies=[Depends(require_api_key)])
def set_detection_status(
    detection_id: str,
    request: DetectionStatusUpdateRequest,
    storage: SQLiteStorage = Depends(get_storage),
) -> dict[str, object]:
    try:
        result = update_detection_status(
            storage,
            detection_id,
            request.status,
            note=request.note,
            evidence=request.evidence,
        )
    except DetectionLifecycleError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if result.status == "not_found":
        raise HTTPException(status_code=404, detail="Detection not found")
    return result.model_dump(mode="json")
