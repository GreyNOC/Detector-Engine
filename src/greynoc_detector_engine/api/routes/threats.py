from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from greynoc_detector_engine.api.dependencies import get_storage
from greynoc_detector_engine.api.pagination import DEFAULT_LIMIT, LimitParam, apply_limit
from greynoc_detector_engine.catalog.threat_query import (
    ThreatQueryFilters,
    ThreatSort,
    filter_threats,
    summarize_threat,
)
from greynoc_detector_engine.models.prediction import ForecastHorizon
from greynoc_detector_engine.models.threat import (
    AIAttackType,
    ThreatRecord,
    ThreatSeverity,
    ThreatStatus,
)
from greynoc_detector_engine.storage.sqlite import SQLiteStorage

router = APIRouter()


@router.get("/threats")
def list_threats(
    query: str | None = Query(default=None),
    severity: ThreatSeverity | None = Query(default=None),
    status: ThreatStatus | None = Query(default=None),
    cve: str | None = Query(default=None),
    product: str | None = Query(default=None),
    actor: str | None = Query(default=None),
    sector: str | None = Query(default=None),
    campaign: str | None = Query(default=None),
    horizon: ForecastHorizon | None = Query(default=None),
    ai_attack_type: AIAttackType | None = Query(default=None),
    min_probability: float | None = Query(default=None, ge=0.0, le=1.0),
    max_probability: float | None = Query(default=None, ge=0.0, le=1.0),
    sort: ThreatSort = Query(default=ThreatSort.PRIORITY),
    summary: bool = Query(default=False),
    limit: LimitParam = DEFAULT_LIMIT,
    storage: SQLiteStorage = Depends(get_storage),
) -> list[dict[str, object]]:
    threats = _query_threats(
        storage,
        query=query,
        severity=severity,
        status=status,
        cve=cve,
        product=product,
        actor=actor,
        sector=sector,
        campaign=campaign,
        horizon=horizon,
        ai_attack_type=ai_attack_type,
        min_probability=min_probability,
        max_probability=max_probability,
        sort=sort,
    )
    return [_serialize_threat(record, summary=summary) for record in apply_limit(threats, limit)]


@router.get("/threats/search")
def search_threats(
    query: str | None = Query(default=None),
    severity: ThreatSeverity | None = Query(default=None),
    status: ThreatStatus | None = Query(default=None),
    cve: str | None = Query(default=None),
    product: str | None = Query(default=None),
    actor: str | None = Query(default=None),
    sector: str | None = Query(default=None),
    campaign: str | None = Query(default=None),
    horizon: ForecastHorizon | None = Query(default=None),
    ai_attack_type: AIAttackType | None = Query(default=None),
    min_probability: float | None = Query(default=None, ge=0.0, le=1.0),
    max_probability: float | None = Query(default=None, ge=0.0, le=1.0),
    sort: ThreatSort = Query(default=ThreatSort.PRIORITY),
    limit: LimitParam = DEFAULT_LIMIT,
    storage: SQLiteStorage = Depends(get_storage),
) -> dict[str, object]:
    threats = _query_threats(
        storage,
        query=query,
        severity=severity,
        status=status,
        cve=cve,
        product=product,
        actor=actor,
        sector=sector,
        campaign=campaign,
        horizon=horizon,
        ai_attack_type=ai_attack_type,
        min_probability=min_probability,
        max_probability=max_probability,
        sort=sort,
    )
    rows = [summarize_threat(record) for record in apply_limit(threats, limit)]
    return {"count": len(rows), "sort": sort.value, "threats": rows}


@router.get("/threats/{threat_id}")
def get_threat(threat_id: str, storage: SQLiteStorage = Depends(get_storage)) -> dict[str, object]:
    record = storage.get_threat(threat_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Threat not found")
    return record.model_dump(mode="json")


def _query_threats(
    storage: SQLiteStorage,
    *,
    query: str | None,
    severity: ThreatSeverity | None,
    status: ThreatStatus | None,
    cve: str | None,
    product: str | None,
    actor: str | None,
    sector: str | None,
    campaign: str | None,
    horizon: ForecastHorizon | None,
    ai_attack_type: AIAttackType | None,
    min_probability: float | None,
    max_probability: float | None,
    sort: ThreatSort,
) -> list[ThreatRecord]:
    if (
        min_probability is not None
        and max_probability is not None
        and min_probability > max_probability
    ):
        raise HTTPException(
            status_code=422,
            detail="min_probability cannot be greater than max_probability",
        )
    filters = ThreatQueryFilters(
        query=query,
        severity=severity,
        status=status,
        cve=cve.upper() if cve else None,
        product=product,
        actor=actor,
        sector=sector,
        campaign=campaign,
        horizon=horizon,
        ai_attack_type=ai_attack_type,
        min_probability=min_probability,
        max_probability=max_probability,
    )
    return filter_threats(storage.list_threats(), filters, sort=sort)


def _serialize_threat(threat: ThreatRecord, *, summary: bool) -> dict[str, object]:
    if summary:
        return summarize_threat(threat)
    return threat.model_dump(mode="json")
