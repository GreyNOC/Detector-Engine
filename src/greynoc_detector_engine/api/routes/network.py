from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException

from greynoc_detector_engine.api.dependencies import get_storage, require_api_key
from greynoc_detector_engine.api.job_locks import single_running_job
from greynoc_detector_engine.api.pagination import LimitQuery, apply_limit
from greynoc_detector_engine.spacestation.orchestrator import (
    run_discovery_job,
    run_sensor_job,
)
from greynoc_detector_engine.storage.sqlite import SQLiteStorage

router = APIRouter(tags=["network"])
Protected = Depends(require_api_key)


@router.post("/network/discover", dependencies=[Protected])
def post_discover(storage: SQLiteStorage = Depends(get_storage)) -> dict[str, Any]:
    """Run passive discovery once; persist devices and ICS classifications."""
    try:
        with single_running_job("network:discover"):
            result = run_discovery_job(storage)
    except HTTPException:
        raise
    except Exception as exc:  # pragma: no cover - defensive surface
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return result.model_dump(mode="json")


@router.get("/network/devices")
def list_devices(
    limit: Annotated[int, LimitQuery],
    storage: SQLiteStorage = Depends(get_storage),
) -> list[dict[str, Any]]:
    return [d.model_dump(mode="json") for d in apply_limit(storage.list_network_devices(), limit)]


@router.get("/network/ics-observations")
def list_ics_observations(
    limit: Annotated[int, LimitQuery],
    storage: SQLiteStorage = Depends(get_storage),
) -> list[dict[str, Any]]:
    return [o.model_dump(mode="json") for o in apply_limit(storage.list_ics_observations(), limit)]


@router.post("/sensor/run", dependencies=[Protected])
def post_sensor_run(storage: SQLiteStorage = Depends(get_storage)) -> dict[str, Any]:
    """Run a one-shot connection-table snapshot + scan detection cycle."""
    try:
        with single_running_job("sensor:run"):
            result = run_sensor_job(storage)
    except HTTPException:
        raise
    except Exception as exc:  # pragma: no cover
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return result.model_dump(mode="json")


@router.get("/sensor/signals")
def list_signals(
    limit: Annotated[int, LimitQuery],
    storage: SQLiteStorage = Depends(get_storage),
) -> list[dict[str, Any]]:
    return [s.model_dump(mode="json") for s in apply_limit(storage.list_intrusion_signals(), limit)]


@router.get("/sensor/honeypot/events")
def list_honeypot_events(
    limit: Annotated[int, LimitQuery],
    storage: SQLiteStorage = Depends(get_storage),
) -> list[dict[str, Any]]:
    return [e.model_dump(mode="json") for e in apply_limit(storage.list_honeypot_events(), limit)]
