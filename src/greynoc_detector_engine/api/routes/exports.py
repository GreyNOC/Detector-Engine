from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Response

from greynoc_detector_engine.api.dependencies import get_storage
from greynoc_detector_engine.detection.export import (
    ExportFormat,
    build_detection_export_bundle,
    render_detection_export_bundle,
)
from greynoc_detector_engine.models.detection import DetectionKind, DetectionStatus
from greynoc_detector_engine.storage.sqlite import SQLiteStorage

router = APIRouter()


@router.get("/exports/detections")
def export_detections(
    status: DetectionStatus = Query(default=DetectionStatus.VALIDATED),
    kind: DetectionKind | None = Query(default=None),
    threat_id: str | None = Query(default=None),
    export_format: ExportFormat = Query(default="json"),
    storage: SQLiteStorage = Depends(get_storage),
) -> Response:
    bundle = build_detection_export_bundle(
        storage.list_detections(),
        status=status,
        kind=kind,
        threat_id=threat_id,
    )
    body = render_detection_export_bundle(bundle, export_format=export_format)
    media_type = "application/json" if export_format == "json" else "text/plain"
    return Response(content=body, media_type=media_type)
