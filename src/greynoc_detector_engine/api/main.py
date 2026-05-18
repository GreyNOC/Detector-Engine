from __future__ import annotations

from collections.abc import Iterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from greynoc_detector_engine import __version__
from greynoc_detector_engine.api.routes import (
    cves,
    detections,
    exports,
    health,
    intelligence,
    kev,
    learning,
    network,
    operations,
    predictions,
    scores,
    sources,
    testing,
    threats,
)
from greynoc_detector_engine.config.settings import get_settings
from greynoc_detector_engine.storage.sqlite import SQLiteStorage
from greynoc_detector_engine.utils.logging import configure_logging


@asynccontextmanager
async def lifespan(app: FastAPI) -> Iterator[None]:
    settings = get_settings()
    storage = SQLiteStorage(settings.database_path)
    storage.initialize()
    app.state.storage = storage
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level)
    app = FastAPI(
        title="GreyNOC Detection Engine",
        version=__version__,
        description="Defensive threat-intelligence and detection catalog API.",
        lifespan=lifespan,
    )
    app.include_router(health.router)
    app.include_router(sources.router)
    app.include_router(threats.router)
    app.include_router(cves.router)
    app.include_router(kev.router)
    app.include_router(detections.router)
    app.include_router(exports.router)
    app.include_router(testing.router)
    app.include_router(intelligence.router)
    app.include_router(scores.router)
    app.include_router(operations.router)
    app.include_router(predictions.router)
    app.include_router(network.router)
    app.include_router(learning.router)
    return app


app = create_app()
