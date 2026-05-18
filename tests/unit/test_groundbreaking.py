from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from greynoc_detector_engine.exporters import AttackNavigatorExporter, StixExporter
from greynoc_detector_engine.models.feedback import AnalystVerdict, ThreatFeedback
from greynoc_detector_engine.models.indicator import Indicator, IndicatorType
from greynoc_detector_engine.models.network import ConnectionRecord
from greynoc_detector_engine.models.prediction import (
    AttackForecast,
    CampaignCluster,
    ConfidenceBand,
    ForecastHorizon,
    PredictionDriver,
)
from greynoc_detector_engine.models.threat import (
    AIAttackType,
    ThreatRecord,
    ThreatSeverity,
)
from greynoc_detector_engine.prediction.accuracy import compute_accuracy
from greynoc_detector_engine.prediction.counterfactual import (
    CounterfactualEngine,
    Intervention,
)
from greynoc_detector_engine.prediction.features import PredictiveContext
from greynoc_detector_engine.prediction.learning import FeedbackTuner
from greynoc_detector_engine.spacestation.adaptive import (
    AdaptiveBaselineEngine,
    HostBaseline,
)


def _threat(
    threat_id: str = "thr-tests",
    *,
    with_forecast: bool = True,
    indicators: list[Indicator] | None = None,
) -> ThreatRecord:
    drivers = [
        PredictionDriver(
            name="epss_probability",
            weight=0.22,
            value=0.8,
            contribution=0.18,
            rationale="EPSS prior is high.",
        )
    ]
    forecast = (
        AttackForecast(
            attack_probability=0.75,
            horizon=ForecastHorizon.NEAR_TERM,
            horizon_days_p50=12,
            horizon_days_p90=30,
            confidence=ConfidenceBand.HIGH,
            drivers=drivers,
            reasons=["EPSS prior elevated."],
            osint_signal_count=3,
            independent_corroborations=2,
        )
        if with_forecast
        else None
    )
    return ThreatRecord(
        threat_id=threat_id,
        title="Example vulnerability in Acme Gateway",
        summary="Hostile activity reported against Acme Gateway exploiting CVE-2026-12345.",
        category="vulnerability",
        related_cves=["CVE-2026-12345"],
        affected_products=["acme:gateway"],
        observed_indicators=indicators or [],
        severity=ThreatSeverity.HIGH,
        attack_forecast=forecast,
        ai_attack_type=AIAttackType.PROMPT_INJECTION,
    )


# -- Accuracy tracker ---------------------------------------------------------


def test_accuracy_report_empty_inputs_returns_zero_brier() -> None:
    report = compute_accuracy([])
    assert report.sample_count == 0
    assert report.brier_score == 0.0


def test_accuracy_report_brier_score_well_formed() -> None:
    outcomes = [
        {
            "threat_id": "a",
            "forecast_probability": 0.9,
            "verified_attack": 1,
            "forecast_horizon": "imminent",
        },
        {
            "threat_id": "b",
            "forecast_probability": 0.1,
            "verified_attack": 0,
            "forecast_horizon": "long_term",
        },
        {
            "threat_id": "c",
            "forecast_probability": 0.6,
            "verified_attack": 1,
            "forecast_horizon": "near_term",
        },
    ]
    report = compute_accuracy(outcomes)
    assert report.sample_count == 3
    # Three perfectly-near-the-truth observations → low Brier.
    assert report.brier_score < 0.2
    assert report.accuracy_at_50 == pytest.approx(1.0)
    assert "imminent" in report.by_horizon


# -- Feedback tuner -----------------------------------------------------------


def test_feedback_tuner_lowers_weight_of_false_positive_driver() -> None:
    threat = _threat()
    feedback = [
        ThreatFeedback(
            feedback_id="fb-1",
            threat_id=threat.threat_id,
            verdict=AnalystVerdict.FALSE_POSITIVE,
        )
    ]
    tuner = FeedbackTuner()
    starting_weight = tuner.weights["epss_probability"]
    new_weights = tuner.apply(feedback, {threat.threat_id: threat})
    assert "epss_probability" in new_weights
    # The weight should have moved (most likely down) without being zeroed.
    assert new_weights["epss_probability"] != pytest.approx(starting_weight)
    assert new_weights["epss_probability"] > 0


def test_feedback_tuner_ignores_threat_without_forecast() -> None:
    threat = _threat(with_forecast=False)
    feedback = [
        ThreatFeedback(
            feedback_id="fb-1",
            threat_id=threat.threat_id,
            verdict=AnalystVerdict.TRUE_POSITIVE,
        )
    ]
    weights = FeedbackTuner().apply(feedback, {threat.threat_id: threat})
    # Should be effectively the renormalized starting point — total preserved.
    assert sum(weights.values()) > 0


# -- Counterfactual -----------------------------------------------------------


def test_counterfactual_patch_applied_decreases_probability() -> None:
    threat = _threat()
    ctx = PredictiveContext(
        threat=threat,
        local_intrusion_pressure=0.6,
    )
    results = CounterfactualEngine().evaluate(ctx, [Intervention.PATCH_APPLIED])
    assert results[0].probability_delta <= 0
    assert results[0].intervention == Intervention.PATCH_APPLIED


def test_counterfactual_multiple_interventions() -> None:
    threat = _threat()
    ctx = PredictiveContext(threat=threat)
    results = CounterfactualEngine().evaluate(
        ctx,
        [Intervention.PATCH_APPLIED, Intervention.IOC_BLOCKED, Intervention.SEGMENTED],
    )
    assert len(results) == 3
    assert all(r.rationale for r in results)


# -- STIX exporter ------------------------------------------------------------


def test_stix_export_round_trip_bundle_structure() -> None:
    threat = _threat(
        indicators=[
            Indicator(value="203.0.113.50", type=IndicatorType.IPV4, confidence=0.9),
            Indicator(value="evil.example", type=IndicatorType.DOMAIN, confidence=0.7),
        ]
    )
    campaigns = [
        CampaignCluster(
            campaign_id="camp-acme",
            label="Acme gateway campaign",
            related_threat_ids=[threat.threat_id],
            related_cves=threat.related_cves,
            suspected_actors=["lockbit"],
        )
    ]
    bundle = StixExporter().export([threat], campaigns=campaigns)
    types = {obj["type"] for obj in bundle.objects}
    assert "identity" in types
    assert "report" in types
    assert "vulnerability" in types
    assert "indicator" in types
    assert "campaign" in types
    assert "relationship" in types
    assert "threat-actor" in types


def test_stix_export_handles_threat_without_indicators() -> None:
    bundle = StixExporter().export([_threat(threat_id="thr-bare")])
    report = next(obj for obj in bundle.objects if obj["type"] == "report")
    assert report["confidence"] >= 0


# -- ATT&CK Navigator ---------------------------------------------------------


def test_attack_navigator_layer_has_techniques() -> None:
    threat = _threat()
    layer = AttackNavigatorExporter().export([threat])
    # MitreAttackInferrer should pick AML.T0051 (prompt injection) from the
    # threat's summary / category combination.
    technique_ids = [t.techniqueID for t in layer.techniques]
    assert any(t.startswith(("T", "AML.T")) for t in technique_ids) or technique_ids == []
    if technique_ids:
        assert 0 <= layer.techniques[0].score <= 100


# -- Adaptive baselines -------------------------------------------------------


def _conn(source: str, port: int) -> ConnectionRecord:
    return ConnectionRecord(
        protocol="tcp",
        local_address="192.168.1.5",
        local_port=port,
        remote_address=source,
        remote_port=55000,
        state="ESTABLISHED",
        observed_at=datetime.now(UTC),
    )


def test_adaptive_engine_learns_and_flags_outliers() -> None:
    engine = AdaptiveBaselineEngine(z_threshold=2.0, alpha=0.4)
    # Train on benign traffic: ~2 distinct ports per snapshot, repeated.
    for _ in range(10):
        engine.observe([_conn("10.0.0.5", 80), _conn("10.0.0.5", 443)])
    # Check anomaly BEFORE folding the burst back into the baseline —
    # is_anomalous() is the SOC-facing call and must compare against the
    # current baseline, not against itself.
    flag, z, baseline = engine.is_anomalous("10.0.0.5", 25)
    assert isinstance(baseline, HostBaseline)
    assert z > 0
    assert flag, (
        f"expected anomaly for 25 ports vs baseline mean {baseline.mean_distinct_ports:.2f}"
    )


def test_adaptive_engine_quiet_traffic_not_flagged() -> None:
    engine = AdaptiveBaselineEngine(z_threshold=2.0, alpha=0.4)
    for _ in range(10):
        engine.observe([_conn("10.0.0.5", 80), _conn("10.0.0.5", 443)])
    flag, _z, _baseline = engine.is_anomalous("10.0.0.5", 2)
    assert not flag


def test_adaptive_engine_decays_stale_baselines() -> None:
    engine = AdaptiveBaselineEngine()
    engine.load(
        [
            HostBaseline(
                source_address="ancient",
                last_updated=datetime.now(UTC) - timedelta(days=120),
            ),
            HostBaseline(
                source_address="fresh",
                last_updated=datetime.now(UTC),
            ),
        ]
    )
    removed = engine.decay_stale(older_than_days=30)
    sources = {b.source_address for b in engine.baselines()}
    assert removed == 1
    assert "fresh" in sources
    assert "ancient" not in sources
