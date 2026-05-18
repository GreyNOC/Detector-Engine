from __future__ import annotations

from fastapi import APIRouter

from greynoc_detection_engine import __version__

router = APIRouter()


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "greynoc-detection-engine", "version": __version__}
