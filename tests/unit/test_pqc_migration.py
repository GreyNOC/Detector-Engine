from __future__ import annotations

from greynoc_detector_engine.analysis.pqc_migration import plan_migration
from greynoc_detector_engine.models.crypto import (
    CryptoAsset,
    MigrationItem,
    MigrationPlan,
    MigrationUrgency,
)


def _inventory() -> list[CryptoAsset]:
    return [
        CryptoAsset.from_algorithm("RSA-2048-KEX"),  # HNDL confidentiality
        CryptoAsset.from_algorithm("ECDSA-P256"),  # signature
        CryptoAsset.from_algorithm("AES-128"),  # Grover-weakened
        CryptoAsset.from_algorithm("ML-KEM-768"),  # quantum-safe
    ]


def _plan() -> MigrationPlan:
    return plan_migration(
        _inventory(),
        crqc_years=10,
        default_shelf_life_years=15,
        default_migration_years=5,
        current_year=2026,
    )


def _item_for(plan: MigrationPlan, algorithm: str) -> MigrationItem:
    matches = [item for item in plan.items if item.asset.algorithm == algorithm]
    assert len(matches) == 1, f"expected exactly one item for {algorithm}"
    return matches[0]


def test_rsa_kex_is_immediate_with_mosca_at_risk_and_mlkem_target() -> None:
    plan = _plan()
    rsa = _item_for(plan, "RSA-2048-KEX")
    assert rsa.urgency is MigrationUrgency.IMMEDIATE
    assert rsa.mosca is not None
    assert rsa.mosca.at_risk is True
    assert rsa.target_algorithms == ["ML-KEM-768"]


def test_ecdsa_signature_is_medium_no_mosca() -> None:
    plan = _plan()
    ecdsa = _item_for(plan, "ECDSA-P256")
    assert ecdsa.urgency is MigrationUrgency.MEDIUM
    assert ecdsa.mosca is None


def test_aes128_is_low_monitor_only() -> None:
    plan = _plan()
    aes = _item_for(plan, "AES-128")
    assert aes.urgency is MigrationUrgency.LOW
    assert aes.target_algorithms == []


def test_mlkem_is_none_already_safe() -> None:
    plan = _plan()
    mlkem = _item_for(plan, "ML-KEM-768")
    assert mlkem.urgency is MigrationUrgency.NONE
    assert mlkem.mosca is None
    assert mlkem.priority_score == 0.0


def test_items_sorted_by_priority_descending() -> None:
    plan = _plan()
    scores = [item.priority_score for item in plan.items]
    assert scores == sorted(scores, reverse=True)
    # The immediate HNDL asset must outrank the already-safe one.
    assert plan.items[0].asset.algorithm == "RSA-2048-KEX"
    assert plan.items[-1].asset.algorithm == "ML-KEM-768"


def test_counts_add_up_to_total_assets() -> None:
    plan = _plan()
    assert plan.total_assets == 4
    total = plan.immediate + plan.high + plan.medium + plan.low + plan.already_safe
    assert total == plan.total_assets
    assert plan.immediate == 1
    assert plan.medium == 1
    assert plan.low == 1
    assert plan.already_safe == 1


def test_summary_reports_immediate_and_earliest_deadline() -> None:
    plan = _plan()
    blob = " ".join(plan.summary)
    assert "immediate" in blob.lower()
    assert "2035" in blob  # earliest disallowed-after across the inventory


def test_deadline_falls_back_to_cnsa_year_when_no_disallowed_after() -> None:
    # A vulnerable signature with no disallowed_after still gets a deadline.
    asset = CryptoAsset.from_algorithm("ECDSA-P384")
    asset = asset.model_copy(update={"disallowed_after": None})
    plan = plan_migration(
        [asset],
        crqc_years=10,
        default_shelf_life_years=15,
        default_migration_years=5,
        current_year=2026,
    )
    assert plan.items[0].deadline_year == 2033


def test_priority_score_within_unit_interval() -> None:
    plan = _plan()
    for item in plan.items:
        assert 0.0 <= item.priority_score <= 1.0
