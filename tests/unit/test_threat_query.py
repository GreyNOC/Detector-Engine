from __future__ import annotations

from greynoc_detector_engine.catalog.threat_query import (
    ThreatQueryFilters,
    ThreatSort,
    filter_threats,
    summarize_threat,
)
from greynoc_detector_engine.models.prediction import (
    AttackForecast,
    ConfidenceBand,
    ForecastHorizon,
)
from greynoc_detector_engine.models.scoring import ScoreResult, score_label
from greynoc_detector_engine.models.threat import ThreatRecord, ThreatSeverity


def _threat(
    title: str,
    *,
    probability: float,
    severity: ThreatSeverity,
    cve: str,
    product: str,
    actor: str,
    sector: str,
) -> ThreatRecord:
    return ThreatRecord(
        title=title,
        summary=f"{actor} activity against {product}",
        category="vulnerability",
        affected_products=[product],
        related_cves=[cve],
        suspected_actors=[actor],
        sectors_at_risk=[sector],
        severity=severity,
        predictive_score=ScoreResult(
            score=probability * 100,
            label=score_label(probability * 100),
        ),
        attack_forecast=AttackForecast(
            attack_probability=probability,
            horizon=ForecastHorizon.IMMINENT,
            horizon_days_p50=3,
            horizon_days_p90=7,
            confidence=ConfidenceBand.HIGH,
        ),
    )


def test_filter_threats_searches_operator_relevant_fields() -> None:
    target = _threat(
        "Edge gateway exploit chatter",
        probability=0.82,
        severity=ThreatSeverity.CRITICAL,
        cve="CVE-2026-10001",
        product="ExampleCorp EdgeGateway",
        actor="Volt Typhoon",
        sector="energy",
    )
    other = _threat(
        "Identity provider advisory",
        probability=0.25,
        severity=ThreatSeverity.MEDIUM,
        cve="CVE-2026-20002",
        product="ExampleID",
        actor="Unknown",
        sector="finance",
    )

    results = filter_threats(
        [other, target],
        ThreatQueryFilters(
            query="edgegateway",
            cve="CVE-2026-10001",
            actor="volt",
            sector="energy",
            min_probability=0.8,
        ),
    )

    assert results == [target]


def test_filter_threats_sorts_by_priority() -> None:
    lower_probability = _threat(
        "Critical but less likely",
        probability=0.45,
        severity=ThreatSeverity.CRITICAL,
        cve="CVE-2026-30003",
        product="ExampleVPN",
        actor="Unknown",
        sector="healthcare",
    )
    higher_probability = _threat(
        "Likely exploitation",
        probability=0.9,
        severity=ThreatSeverity.LOW,
        cve="CVE-2026-40004",
        product="ExampleCMS",
        actor="Unknown",
        sector="retail",
    )

    results = filter_threats(
        [lower_probability, higher_probability],
        ThreatQueryFilters(),
        sort=ThreatSort.PRIORITY,
    )

    assert results == [higher_probability, lower_probability]


def test_summarize_threat_exposes_triage_fields() -> None:
    threat = _threat(
        "Edge gateway exploit chatter",
        probability=0.82,
        severity=ThreatSeverity.CRITICAL,
        cve="CVE-2026-10001",
        product="ExampleCorp EdgeGateway",
        actor="Volt Typhoon",
        sector="energy",
    )

    summary = summarize_threat(threat)

    assert summary["attack_probability"] == 0.82
    assert summary["affected_products"] == ["ExampleCorp EdgeGateway"]
    assert summary["suspected_actors"] == ["Volt Typhoon"]
    assert summary["sectors_at_risk"] == ["energy"]
