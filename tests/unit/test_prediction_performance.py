from __future__ import annotations

import time
from datetime import datetime
from pathlib import Path

from tests.fixtures.forecast_benchmark import build_prediction_benchmark

from greynoc_detector_engine.enrich.asset_context import AssetInventory
from greynoc_detector_engine.models.asset import AssetRecord, TargetLikelihood
from greynoc_detector_engine.models.cve import CVERecord
from greynoc_detector_engine.models.kev import KEVRecord
from greynoc_detector_engine.models.prediction import EPSSScore, ForecastHorizon
from greynoc_detector_engine.models.source import SourceItem
from greynoc_detector_engine.models.threat import ThreatRecord
from greynoc_detector_engine.prediction.attack_forecast import AttackForecaster
from greynoc_detector_engine.prediction.counterfactual import (
    CounterfactualEngine,
    Intervention,
)
from greynoc_detector_engine.prediction.features import PredictiveContext
from greynoc_detector_engine.prediction.signal_index import PredictionSignalIndex
from greynoc_detector_engine.storage.sqlite import SQLiteStorage
from greynoc_detector_engine.utils.hashing import stable_hash
from greynoc_detector_engine.utils.time import utc_now
from greynoc_detector_engine.workers.jobs import run_predict_job


def _cve(cve_id: str = "CVE-2026-12345", *, exploit_refs: int = 0) -> CVERecord:
    return CVERecord(
        cve_id=cve_id,
        description="Example vulnerability",
        cvss_score=9.8,
        exploit_references=[f"https://example.test/poc/{idx}" for idx in range(exploit_refs)],
    )


def _threat(cve_id: str = "CVE-2026-12345") -> ThreatRecord:
    return ThreatRecord(
        threat_id=f"thr-{cve_id.lower()}",
        title=f"Threat {cve_id}",
        summary="Example threat.",
        category="vulnerability",
        related_cves=[cve_id],
        affected_products=["Acme Gateway"],
        last_seen=utc_now(),
    )


def _source_item(cve_id: str = "CVE-2026-12345") -> SourceItem:
    content = f"{cve_id} exploit activity reported with defensive guidance."
    return SourceItem(
        item_id=f"src-{cve_id.lower()}",
        source_id="trusted-blog",
        title=f"Report on {cve_id}",
        raw_content=content,
        raw_excerpt=content,
        content_hash=stable_hash(content),
        confidence=0.9,
    )


def test_signal_index_precomputes_cve_signals() -> None:
    items = [_source_item(), _source_item("CVE-2026-54321")]
    index = PredictionSignalIndex.build(items)
    signal = index.signal_for_cves(["CVE-2026-12345"])

    assert signal.raw_items_scanned == 2
    assert signal.source_diversity == 1
    assert signal.trusted_source_count == 1
    assert signal.cve_mention_count == 1
    assert signal.chatter_velocity > 0


def test_predict_run_records_metrics_and_skips_unchanged_inputs(tmp_path: Path) -> None:
    storage = SQLiteStorage(tmp_path / "predict.sqlite")
    storage.initialize()
    storage.upsert_cve(_cve())
    storage.upsert_threat(_threat())
    storage.upsert_raw_item(_source_item())

    first = run_predict_job(storage)
    second = run_predict_job(storage)

    assert first.counts["forecasts"] == 1
    assert second.counts["skipped"] == 1
    assert storage.get_latest_forecast_for_threat("thr-cve-2026-12345") is not None
    runs = storage.list_forecast_runs()
    assert len(runs) == 2
    assert runs[0].raw_items_scanned == 1
    assert runs[0].forecast_latency_p95 >= 0
    assert runs[0].threats_per_second >= 0


def test_predict_run_force_recomputes_unchanged_inputs(tmp_path: Path) -> None:
    storage = SQLiteStorage(tmp_path / "predict.sqlite")
    storage.initialize()
    storage.upsert_cve(_cve())
    storage.upsert_threat(_threat())
    storage.upsert_raw_item(_source_item())

    run_predict_job(storage)
    forced = run_predict_job(storage, force=True)

    assert forced.counts["forecasts"] == 1
    assert forced.counts["skipped"] == 0


def test_target_likelihood_upsert_avoids_duplicates(tmp_path: Path) -> None:
    storage = SQLiteStorage(tmp_path / "predict.sqlite")
    storage.initialize()
    first = TargetLikelihood(
        asset_id="asset-1",
        threat_id="thr-1",
        likelihood=0.4,
        blast_radius=0.8,
        reasons=["initial"],
    )
    second = first.model_copy(update={"likelihood": 0.7, "reasons": ["updated"]})

    storage.record_target_likelihood(first)
    storage.record_target_likelihood(second)

    likelihoods = storage.list_target_likelihoods_for_threat("thr-1")
    assert len(likelihoods) == 1
    assert likelihoods[0].likelihood == 0.7
    assert likelihoods[0].reasons == ["updated"]


def test_forecast_probability_monotonic_for_stronger_signals() -> None:
    threat = _threat()
    forecaster = AttackForecaster()
    baseline = forecaster.forecast(PredictiveContext(threat=threat)).attack_probability
    kev = KEVRecord(
        cve_id="CVE-2026-12345",
        vendor_project="Acme",
        product="Gateway",
        vulnerability_name="Example",
        short_description="Example",
        required_action="Patch",
    )
    epss = EPSSScore(
        cve_id="CVE-2026-12345",
        epss=0.8,
        percentile=0.95,
        score_date=datetime.fromisoformat("2026-05-18T00:00:00+00:00"),
    )
    stronger = forecaster.forecast(
        PredictiveContext(
            threat=threat,
            cve=_cve(exploit_refs=2),
            kev=kev,
            epss=epss,
            local_intrusion_pressure=0.8,
        )
    )

    assert stronger.attack_probability >= baseline
    assert stronger.horizon == ForecastHorizon.IMMINENT


def test_counterfactual_segmentation_decreases_probability() -> None:
    threat = _threat()
    ctx = PredictiveContext(threat=threat, local_intrusion_pressure=0.8)
    result = CounterfactualEngine().evaluate(ctx, [Intervention.SEGMENTED])[0]

    assert result.probability_delta <= 0


def test_asset_inventory_uses_indexed_candidate_lookup() -> None:
    inventory = AssetInventory(
        [
            AssetRecord(asset_id="asset-1", name="Acme Gateway", vendor="Acme", product="Gateway"),
            AssetRecord(
                asset_id="asset-2",
                name="Other Service",
                vendor="Other",
                product="Service",
            ),
        ]
    )
    matches = inventory.match_threat(_threat())

    assert [match.asset.asset_id for match in matches] == ["asset-1"]
    assert "Acme Gateway" in matches[0].matched_product


def test_signal_index_10k_fixture_performance_budget() -> None:
    threats, items = build_prediction_benchmark(10_000)
    started = time.perf_counter()
    index = PredictionSignalIndex.build(items)
    for threat in threats[:1_000]:
        assert index.signal_for_cves(threat.related_cves).cve_mention_count == 1
    elapsed = time.perf_counter() - started

    assert elapsed < 10.0
