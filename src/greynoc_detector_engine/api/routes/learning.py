from __future__ import annotations

from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Body, Depends, HTTPException

from greynoc_detector_engine.api.dependencies import get_storage, require_api_key
from greynoc_detector_engine.exporters import AttackNavigatorExporter, StixExporter
from greynoc_detector_engine.models.feedback import AnalystVerdict, ThreatFeedback
from greynoc_detector_engine.prediction.accuracy import compute_accuracy
from greynoc_detector_engine.prediction.counterfactual import (
    CounterfactualEngine,
    Intervention,
)
from greynoc_detector_engine.prediction.features import PredictiveContext
from greynoc_detector_engine.prediction.learning import FeedbackTuner
from greynoc_detector_engine.storage.sqlite import SQLiteStorage

router = APIRouter(tags=["learning"])
Protected = Depends(require_api_key)


@router.post("/feedback", dependencies=[Protected])
def submit_feedback(
    payload: dict[str, Any] = Body(...),
    storage: SQLiteStorage = Depends(get_storage),
) -> dict[str, Any]:
    try:
        verdict = AnalystVerdict(payload.get("verdict", ""))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    threat_id = payload.get("threat_id")
    if not isinstance(threat_id, str) or not threat_id:
        raise HTTPException(status_code=400, detail="threat_id is required")
    feedback = ThreatFeedback(
        feedback_id=f"fb-{uuid4().hex[:12]}",
        threat_id=threat_id,
        verdict=verdict,
        analyst=str(payload.get("analyst", "anonymous"))[:128],
        notes=str(payload.get("notes", ""))[:2048],
    )
    storage.upsert_threat_feedback(feedback)
    all_feedback = storage.list_threat_feedback()
    threats_by_id = {t.threat_id: t for t in storage.list_threats()}
    new_weights = FeedbackTuner().apply(all_feedback, threats_by_id)
    return {
        "feedback_id": feedback.feedback_id,
        "applied_weights": new_weights,
    }


@router.get("/feedback")
def list_feedback(storage: SQLiteStorage = Depends(get_storage)) -> list[dict[str, Any]]:
    return [fb.model_dump(mode="json") for fb in storage.list_threat_feedback()]


@router.get("/predict/accuracy")
def get_accuracy(storage: SQLiteStorage = Depends(get_storage)) -> dict[str, Any]:
    outcomes = storage.list_forecast_outcomes()
    return compute_accuracy(outcomes).model_dump(mode="json")


@router.post("/predict/counterfactual/{threat_id}", dependencies=[Protected])
def post_counterfactual(
    threat_id: str,
    payload: dict[str, Any] = Body(default_factory=dict),
    storage: SQLiteStorage = Depends(get_storage),
) -> list[dict[str, Any]]:
    threat = storage.get_threat(threat_id)
    if threat is None:
        raise HTTPException(status_code=404, detail="Threat not found")
    cve = storage.get_cve(threat.related_cves[0]) if threat.related_cves else None
    kev = storage.get_kev(threat.related_cves[0]) if threat.related_cves else None
    raw_interventions = payload.get("interventions") or [
        "patch_applied",
        "ioc_blocked",
        "segmented",
        "detection_deployed",
    ]
    if not isinstance(raw_interventions, list):
        raise HTTPException(status_code=400, detail="interventions must be a list")
    parsed: list[Intervention] = []
    for raw in raw_interventions:
        try:
            parsed.append(Intervention(str(raw)))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    ctx = PredictiveContext(threat=threat, cve=cve, kev=kev)
    results = CounterfactualEngine().evaluate(ctx, parsed)
    return [r.model_dump(mode="json") for r in results]


@router.get("/export/stix")
def export_stix(storage: SQLiteStorage = Depends(get_storage)) -> dict[str, Any]:
    bundle = StixExporter().export(
        threats=storage.list_threats(),
        campaigns=storage.list_campaigns(),
    )
    return bundle.model_dump(mode="json")


@router.get("/export/attack-navigator")
def export_attack_navigator(
    storage: SQLiteStorage = Depends(get_storage),
) -> dict[str, Any]:
    layer = AttackNavigatorExporter().export(storage.list_threats())
    return layer.model_dump(mode="json")
