from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict

from greynoc_detector_engine.api.dependencies import get_storage, require_api_key
from greynoc_detector_engine.detection.testing import (
    DetectionFixture,
    DetectionTestCase,
    run_detection_test_case,
)
from greynoc_detector_engine.storage.sqlite import SQLiteStorage

router = APIRouter()


class DetectionTestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fixtures: list[DetectionFixture]


@router.post("/detections/{detection_id}/test", dependencies=[Depends(require_api_key)])
def test_detection(
    detection_id: str,
    request: DetectionTestRequest,
    storage: SQLiteStorage = Depends(get_storage),
) -> dict[str, object]:
    detection = storage.get_detection(detection_id)
    if detection is None:
        raise HTTPException(status_code=404, detail="Detection not found")
    report = run_detection_test_case(
        detection,
        DetectionTestCase(detection_id=detection_id, fixtures=request.fixtures),
    )
    return report.model_dump(mode="json")
