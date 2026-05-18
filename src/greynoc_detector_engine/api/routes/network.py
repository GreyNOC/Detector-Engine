from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from greynoc_detector_engine.api.dependencies import get_storage
from greynoc_detector_engine.spacestation.orchestrator import (
    run_discovery_job,
    run_sensor_job,
)
from greynoc_detector_engine.storage.sqlite import SQLiteStorage

router = APIRouter(tags=["network"])


@router.post("/network/discover")
def post_discover(storage: SQLiteStorage = Depends(get_storage)) -> dict[str, Any]:
    """Run passive discovery once; persist devices and ICS classifications."""
    try:
        result = run_discovery_job(storage)
    except Exception as exc:  # pragma: no cover - defensive surface
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return result.model_dump(mode="json")


@router.get("/network/devices")
def list_devices(storage: SQLiteStorage = Depends(get_storage)) -> list[dict[str, Any]]:
    return [d.model_dump(mode="json") for d in storage.list_network_devices()]


@router.get("/network/ics-observations")
def list_ics_observations(storage: SQLiteStorage = Depends(get_storage)) -> list[dict[str, Any]]:
    return [o.model_dump(mode="json") for o in storage.list_ics_observations()]


@router.post("/sensor/run")
def post_sensor_run(storage: SQLiteStorage = Depends(get_storage)) -> dict[str, Any]:
    """Run a one-shot connection-table snapshot + scan detection cycle."""
    try:
        result = run_sensor_job(storage)
    except Exception as exc:  # pragma: no cover
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return result.model_dump(mode="json")


@router.get("/sensor/signals")
def list_signals(storage: SQLiteStorage = Depends(get_storage)) -> list[dict[str, Any]]:
    return [s.model_dump(mode="json") for s in storage.list_intrusion_signals()]


@router.get("/sensor/honeypot/events")
def list_honeypot_events(storage: SQLiteStorage = Depends(get_storage)) -> list[dict[str, Any]]:
    return [e.model_dump(mode="json") for e in storage.list_honeypot_events()]
