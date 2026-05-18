from __future__ import annotations

from fastapi import APIRouter, Depends

from greynoc_detector_engine.api.dependencies import get_app_settings
from greynoc_detector_engine.config.settings import Settings, load_source_registry

router = APIRouter()


@router.get("/sources")
def list_sources(settings: Settings = Depends(get_app_settings)) -> dict[str, object]:
    registry = load_source_registry(settings.sources_path)
    return {
        "count": len(registry.sources),
        "sources": [source.model_dump(mode="json", by_alias=True) for source in registry.sources],
    }
