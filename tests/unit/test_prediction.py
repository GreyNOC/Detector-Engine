from __future__ import annotations

from datetime import timedelta

from greynoc_detector_engine.enrich.epss import EPSSEnricher
from greynoc_detector_engine.enrich.reputation import (
    IndicatorReputation,
    IndicatorReputationEngine,
    ReputationVerdict,
)
from greynoc_detector_engine.enrich.threat_actor import ThreatActorAttributor
from greynoc_detector_engine.models.cve import CVERecord
from greynoc_detector_engine.models.indicator import IndicatorType
from greynoc_detector_engine.models.kev import KEVRecord
from greynoc_detector_engine.models.prediction import ForecastHorizon
from greynoc_detector_engine.models.threat import ThreatRecord
from greynoc_detector_engine.prediction.attack_forecast import AttackForecaster
from greynoc_detector_engine.prediction.exploit_timing import ExploitTimingModel
from greynoc_detector_engine.prediction.features import (
    PredictiveContext,
    PredictiveFeatureBuilder,
    PredictiveFeatures,
)
from greynoc_detector_engine.prediction.weaponization import WeaponizationModel
from greynoc_detector_engine.utils.time import utc_now


def _threat(**overrides: object) -> ThreatRecord:
    defaults: dict[str, object] = {
        "title": "Test threat",
        "summary": "summary",
        "category": "vulnerability",
        "related_cves": ["CVE-2026-12345"],
        "last_seen": utc_now(),
    }
    defaults.update(overrides)
    return ThreatRecord(**defaults)  # type: ignore[arg-type]


def _cve() -> CVERecord:
    return CVERecord(
        cve_id="CVE-2026-12345",
        description="Example RCE",
        cvss_score=9.8,
        exploit_references=[
            "https://github.com/example/poc",
            "https://exploit-db.example/42",
        ],
    )


def test_epss_payload_parsing() -> None:
    payload = {
        "data": [
            {"cve": "CVE-2026-12345", "epss": "0.91", "percentile": "0.99", "date": "2026-05-17"},
            {"cve": "bad-row", "epss": "x"},
        ]
    }
    scores = EPSSEnricher.from_first_org_payload(payload)
    assert len(scores) == 1
    assert scores[0].cve_id == "CVE-2026-12345"
    assert 0.0 <= scores[0].epss <= 1.0


def test_predictive_features_are_bounded() -> None:
    builder = PredictiveFeatureBuilder()
    ctx = PredictiveContext(threat=_threat(), cve=_cve())
    features = builder.build(ctx)
    for name, value in features.as_dict().items():
        assert 0.0 <= value <= 1.0, name


def test_exploit_timing_imminent_when_kev_listed() -> None:
    features = PredictiveFeatures(kev_listed=1.0, cvss_pressure=0.9)
    estimate = ExploitTimingModel().estimate(features)
    assert estimate.horizon == ForecastHorizon.IMMINENT
    assert estimate.p50_days == 0


def test_exploit_timing_long_when_no_signal() -> None:
    estimate = ExploitTimingModel().estimate(PredictiveFeatures())
    assert estimate.horizon in {ForecastHorizon.LONG_TERM, ForecastHorizon.MID_TERM}


def test_weaponization_probability_is_in_range() -> None:
    features = PredictiveFeatures(
        kev_listed=1.0,
        public_exploit_availability=1.0,
        ransomware_proximity=1.0,
        actor_activity=1.0,
        epss_probability=0.9,
    )
    estimate = WeaponizationModel().estimate(features)
    assert 0.0 <= estimate.probability <= 1.0
    assert estimate.probability > 0.7  # high signal -> high weaponization


def test_attack_forecast_explains_drivers() -> None:
    kev = KEVRecord(
        cve_id="CVE-2026-12345",
        vendor_project="Example",
        product="Example",
        vulnerability_name="Example RCE",
        short_description="Example",
        required_action="Patch immediately",
        known_ransomware_campaign_use="Known",
    )
    ctx = PredictiveContext(
        threat=_threat(),
        cve=_cve(),
        kev=kev,
        suspected_actors=["lockbit"],
        ransomware_claims_last_30d=5,
        campaign_active=True,
    )
    forecast = AttackForecaster().forecast(ctx)
    assert forecast.attack_probability > 0.5
    assert forecast.horizon == ForecastHorizon.IMMINENT
    driver_names = {d.name for d in forecast.drivers}
    assert "kev_listed" in driver_names
    assert any("CISA KEV" in r for r in forecast.reasons)


def test_indicator_reputation_engine_picks_strongest_verdict() -> None:
    engine = IndicatorReputationEngine()
    engine.upsert(
        IndicatorReputation(
            value="evil.example",
            type=IndicatorType.DOMAIN,
            verdict=ReputationVerdict.SUSPICIOUS,
            confidence=0.5,
            sources=["a"],
        )
    )
    engine.upsert(
        IndicatorReputation(
            value="evil.example",
            type=IndicatorType.DOMAIN,
            verdict=ReputationVerdict.MALICIOUS,
            confidence=0.8,
            sources=["b"],
        )
    )
    merged_lookup = engine.lookup(
        type("X", (), {"value": "evil.example", "type": IndicatorType.DOMAIN, "source": None})()
    )
    assert merged_lookup.verdict == ReputationVerdict.MALICIOUS
    assert "a" in merged_lookup.sources and "b" in merged_lookup.sources


def test_threat_actor_attribution_finds_aliases() -> None:
    attributor = ThreatActorAttributor()
    actors = attributor.actor_ids("Mandiant reported activity by Fancy Bear targeting NATO.")
    assert "apt28" in actors


def test_predictive_engine_no_signal_returns_low_probability() -> None:
    quiet = _threat(last_seen=utc_now() - timedelta(days=120))
    forecast = AttackForecaster().forecast(PredictiveContext(threat=quiet))
    assert 0.0 <= forecast.attack_probability <= 0.5
