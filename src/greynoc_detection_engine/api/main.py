from __future__ import annotations

from fastapi import FastAPI

from greynoc_detection_engine.api.routes import (
    cves,
    detections,
    health,
    kev,
    operations,
    sources,
    threats,
)
from greynoc_detection_engine.config.settings import get_settings
from greynoc_detection_engine.utils.logging import configure_logging


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level)
    app = FastAPI(
        title="GreyNOC Detection Engine",
        version="0.1.0",
        description="Defensive threat-intelligence and detection catalog API.",
    )
    app.include_router(health.router)
    app.include_router(sources.router)
    app.include_router(threats.router)
    app.include_router(cves.router)
    app.include_router(kev.router)
    app.include_router(detections.router)
    app.include_router(operations.router)
    return app


app = create_app()
