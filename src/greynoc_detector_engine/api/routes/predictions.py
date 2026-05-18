from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from greynoc_detector_engine.api.dependencies import get_app_settings, get_storage
from greynoc_detector_engine.api.safety import validate_fixture_path
from greynoc_detector_engine.config.settings import Settings
from greynoc_detector_engine.storage.sqlite import SQLiteStorage
from greynoc_detector_engine.workers.jobs import run_predict_job

router = APIRouter(tags=["predictions"])


@router.post("/predict/run")
def run_prediction(
    asset_inventory: str | None = Query(default=None),
    settings: Settings = Depends(get_app_settings),
    storage: SQLiteStorage = Depends(get_storage),
) -> dict[str, Any]:
    """Re-run the predictive layer against existing stored threats."""
    inv = validate_fixture_path(asset_inventory, settings)
    result = run_predict_job(storage, asset_inventory_path=inv)
    return result.model_dump(mode="json")


@router.get("/predict/forecasts/{threat_id}")
def get_forecasts(
    threat_id: str,
    storage: SQLiteStorage = Depends(get_storage),
) -> list[dict[str, Any]]:
    threat = storage.get_threat(threat_id)
    if threat is None:
        raise HTTPException(status_code=404, detail="Threat not found")
    return [f.model_dump(mode="json") for f in storage.list_forecasts_for_threat(threat_id)]


@router.get("/predict/threat/{threat_id}")
def get_threat_with_prediction(
    threat_id: str,
    storage: SQLiteStorage = Depends(get_storage),
) -> dict[str, Any]:
    threat = storage.get_threat(threat_id)
    if threat is None:
        raise HTTPException(status_code=404, detail="Threat not found")
    likelihoods = storage.list_target_likelihoods_for_threat(threat_id)
    return {
        "threat": threat.model_dump(mode="json"),
        "target_likelihoods": [tl.model_dump(mode="json") for tl in likelihoods],
    }


@router.get("/predict/imminent")
def list_imminent(
    min_probability: float = Query(default=0.5, ge=0.0, le=1.0),
    storage: SQLiteStorage = Depends(get_storage),
) -> list[dict[str, Any]]:
    """Return threats whose forecast is IMMINENT or NEAR_TERM above a threshold."""
    out: list[dict[str, Any]] = []
    for threat in storage.list_threats():
        forecast = threat.attack_forecast
        if forecast is None:
            continue
        if forecast.horizon.value not in {"imminent", "near_term"}:
            continue
        if forecast.attack_probability < min_probability:
            continue
        out.append(
            {
                "threat_id": threat.threat_id,
                "title": threat.title,
                "attack_probability": forecast.attack_probability,
                "horizon": forecast.horizon.value,
                "horizon_days_p50": forecast.horizon_days_p50,
                "confidence": forecast.confidence.value,
                "related_cves": threat.related_cves,
                "campaign_ids": threat.campaign_ids,
                "suspected_actors": threat.suspected_actors,
                "reasons": forecast.reasons[:6],
            }
        )
    out.sort(key=lambda row: float(row["attack_probability"]), reverse=True)
    return out


@router.get("/campaigns")
def list_campaigns(storage: SQLiteStorage = Depends(get_storage)) -> list[dict[str, Any]]:
    return [c.model_dump(mode="json") for c in storage.list_campaigns()]


@router.get("/campaigns/{campaign_id}")
def get_campaign(
    campaign_id: str,
    storage: SQLiteStorage = Depends(get_storage),
) -> dict[str, Any]:
    campaign = storage.get_campaign(campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return campaign.model_dump(mode="json")
