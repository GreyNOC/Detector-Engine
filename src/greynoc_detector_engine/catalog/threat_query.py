from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from greynoc_detector_engine.models.prediction import ForecastHorizon
from greynoc_detector_engine.models.threat import (
    AIAttackType,
    ThreatRecord,
    ThreatSeverity,
    ThreatStatus,
)


class ThreatSort(StrEnum):
    PRIORITY = "priority"
    PROBABILITY = "probability"
    SEVERITY = "severity"
    CONFIDENCE = "confidence"
    LAST_SEEN = "last_seen"
    FIRST_SEEN = "first_seen"
    TITLE = "title"


@dataclass(frozen=True)
class ThreatQueryFilters:
    query: str | None = None
    severity: ThreatSeverity | None = None
    status: ThreatStatus | None = None
    cve: str | None = None
    product: str | None = None
    actor: str | None = None
    sector: str | None = None
    campaign: str | None = None
    horizon: ForecastHorizon | None = None
    ai_attack_type: AIAttackType | None = None
    min_probability: float | None = None
    max_probability: float | None = None


def filter_threats(
    threats: Iterable[ThreatRecord],
    filters: ThreatQueryFilters,
    *,
    sort: ThreatSort = ThreatSort.PRIORITY,
) -> list[ThreatRecord]:
    """Apply operator-facing triage filters and stable sorting."""

    matches = [threat for threat in threats if _matches_filters(threat, filters)]
    return sort_threats(matches, sort)


def sort_threats(threats: Iterable[ThreatRecord], sort: ThreatSort) -> list[ThreatRecord]:
    if sort == ThreatSort.TITLE:
        return sorted(threats, key=lambda threat: threat.title.casefold())
    if sort == ThreatSort.FIRST_SEEN:
        return sorted(
            threats,
            key=lambda threat: threat.first_seen.isoformat() if threat.first_seen else "",
            reverse=True,
        )
    if sort == ThreatSort.LAST_SEEN:
        return sorted(
            threats,
            key=lambda threat: threat.last_seen.isoformat() if threat.last_seen else "",
            reverse=True,
        )
    if sort == ThreatSort.CONFIDENCE:
        return sorted(threats, key=lambda threat: threat.confidence, reverse=True)
    if sort == ThreatSort.SEVERITY:
        return sorted(threats, key=_severity_sort_key, reverse=True)
    if sort == ThreatSort.PROBABILITY:
        return sorted(threats, key=_probability_sort_key, reverse=True)
    return sorted(threats, key=_priority_sort_key, reverse=True)


def summarize_threat(threat: ThreatRecord) -> dict[str, Any]:
    forecast = threat.attack_forecast
    predictive_score = threat.predictive_score
    return {
        "threat_id": threat.threat_id,
        "title": threat.title,
        "severity": threat.severity.value,
        "status": threat.status.value,
        "confidence": threat.confidence,
        "predictive_score": predictive_score.score if predictive_score is not None else None,
        "attack_probability": forecast.attack_probability if forecast is not None else None,
        "horizon": forecast.horizon.value if forecast is not None else None,
        "related_cves": threat.related_cves,
        "affected_products": threat.affected_products,
        "suspected_actors": threat.suspected_actors,
        "campaign_ids": threat.campaign_ids,
        "sectors_at_risk": threat.sectors_at_risk,
        "recommended_soc_actions": threat.recommended_soc_actions[:5],
    }


def _matches_filters(threat: ThreatRecord, filters: ThreatQueryFilters) -> bool:
    if filters.severity is not None and threat.severity != filters.severity:
        return False
    if filters.status is not None and threat.status != filters.status:
        return False
    if filters.ai_attack_type is not None and threat.ai_attack_type != filters.ai_attack_type:
        return False
    if filters.horizon is not None and (
        threat.attack_forecast is None or threat.attack_forecast.horizon != filters.horizon
    ):
        return False
    if filters.cve is not None and not _matches_exact_list(
        [*threat.related_cves, *threat.related_kev_entries],
        filters.cve,
    ):
        return False
    if filters.product is not None and not _contains_any(
        threat.affected_products,
        filters.product,
    ):
        return False
    if filters.actor is not None and not _contains_any(threat.suspected_actors, filters.actor):
        return False
    if filters.sector is not None and not _contains_any(threat.sectors_at_risk, filters.sector):
        return False
    if filters.campaign is not None and not _matches_exact_list(
        threat.campaign_ids,
        filters.campaign,
    ):
        return False
    if filters.min_probability is not None or filters.max_probability is not None:
        probability = (
            threat.attack_forecast.attack_probability
            if threat.attack_forecast is not None
            else None
        )
        if probability is None:
            return False
        if filters.min_probability is not None and probability < filters.min_probability:
            return False
        if filters.max_probability is not None and probability > filters.max_probability:
            return False
    return filters.query is None or _contains_any(_searchable_strings(threat), filters.query)


def _contains_any(values: Iterable[str], needle: str) -> bool:
    normalized = needle.strip().casefold()
    if not normalized:
        return True
    return any(normalized in value.casefold() for value in values if value)


def _matches_exact_list(values: Iterable[str], needle: str) -> bool:
    normalized = needle.strip().casefold()
    if not normalized:
        return True
    return any(normalized == value.casefold() for value in values if value)


def _searchable_strings(threat: ThreatRecord) -> list[str]:
    values = [
        threat.threat_id,
        threat.title,
        threat.summary,
        threat.category,
        threat.severity.value,
        threat.status.value,
    ]
    if threat.ai_attack_type is not None:
        values.append(threat.ai_attack_type.value)
    values.extend(threat.affected_products)
    values.extend(threat.related_cves)
    values.extend(threat.related_kev_entries)
    values.extend(threat.tactics_techniques_procedures)
    values.extend(threat.mitre_attack_mapping)
    values.extend(threat.suspected_actors)
    values.extend(threat.campaign_ids)
    values.extend(threat.sectors_at_risk)
    values.extend(threat.recommended_soc_actions)
    values.extend(threat.detection_opportunities)
    for indicator in threat.observed_indicators:
        values.append(indicator.value)
        values.append(indicator.type.value)
        if indicator.source is not None:
            values.append(indicator.source)
        if indicator.context is not None:
            values.append(indicator.context)
    for reference in threat.source_references:
        values.append(reference.title)
        values.append(reference.source)
        values.append(reference.raw_excerpt)
        if reference.author is not None:
            values.append(reference.author)
        if reference.url is not None:
            values.append(reference.url)
    for detection in threat.generated_detections:
        values.append(detection.title)
        values.append(detection.description)
        values.append(detection.kind.value)
        values.extend(detection.required_telemetry)
    return values


def _severity_sort_key(threat: ThreatRecord) -> tuple[float, float]:
    return (_severity_weight(threat.severity), threat.confidence)


def _probability_sort_key(threat: ThreatRecord) -> tuple[float, float, float]:
    forecast = threat.attack_forecast
    probability = forecast.attack_probability if forecast is not None else 0.0
    return (probability, _severity_weight(threat.severity), threat.confidence)


def _priority_sort_key(threat: ThreatRecord) -> tuple[float, float, float, float]:
    predictive_score = threat.predictive_score.score if threat.predictive_score is not None else 0.0
    probability, severity, confidence = _probability_sort_key(threat)
    return (probability, severity, predictive_score, confidence)


def _severity_weight(severity: ThreatSeverity) -> float:
    return {
        ThreatSeverity.CRITICAL: 4.0,
        ThreatSeverity.HIGH: 3.0,
        ThreatSeverity.MEDIUM: 2.0,
        ThreatSeverity.LOW: 1.0,
    }[severity]
