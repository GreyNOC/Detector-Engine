"""Prioritized, glass-box post-quantum migration planner.

Given a crypto inventory (:class:`~greynoc_detector_engine.models.crypto.CryptoAsset`
records, typically built via :meth:`CryptoAsset.from_algorithm`) this module
produces an ordered :class:`MigrationPlan`: for every asset it decides *how
urgent* migration is, *what to migrate to*, *by when*, and *why*.

Everything here is deterministic arithmetic over the authoritative algorithm
registry plus Mosca's inequality -- there is no model, no clock, and no network.
``current_year`` is an explicit parameter so a plan is reproducible: the same
inventory and horizons always yield the same plan.

Urgency ladder (most to least urgent):

  * **IMMEDIATE** -- a confidentiality / harvest-now-decrypt-later (HNDL) asset
    that is *already* at risk: either Mosca's inequality trips for it, or its
    NIST IR 8547 disallowed-after deadline lands within five years. Recorded
    traffic is exposed retroactively, so there is no slack.
  * **HIGH** -- a quantum-vulnerable confidentiality (HNDL) asset that is not yet
    immediate. Still records-now exposure, but with budget left.
  * **MEDIUM** -- a quantum-vulnerable signature / authenticity primitive.
    Forgery needs a CRQC *at attack time*, not retroactively, so the clock is
    the CRQC arrival rather than today.
  * **LOW** -- a Grover-*weakened* primitive (AES-128, SHA-256): still adequate,
    monitor only.
  * **NONE** -- already quantum-safe (a PQ or hash-based design).

The ``priority_score`` is a documented weighted blend (see :data:`_WEIGHTS`),
not a black box: each component is recorded in the item rationale.
"""

from __future__ import annotations

from greynoc_detector_engine.analysis.mosca import assess_mosca
from greynoc_detector_engine.crypto.algorithms import (
    CNSA_2_0_EXCLUSIVE_YEAR,
    QuantumThreat,
)
from greynoc_detector_engine.crypto.algorithms import (
    recommended_replacements as registry_replacements,
)
from greynoc_detector_engine.models.crypto import (
    CryptoAsset,
    MigrationItem,
    MigrationPlan,
    MigrationUrgency,
    MoscaAssessment,
)

# How many years out a disallowed-after deadline still counts as "act now".
IMMEDIATE_DEADLINE_HORIZON_YEARS = 5

# Glass-box priority weights. They sum to 1.0; each scales a normalized [0,1]
# component so the final score stays in [0,1]. The blend is intentionally simple
# and auditable -- see _score() for how each component is computed.
_WEIGHTS: dict[str, float] = {
    "hndl": 0.40,  # confidentiality / harvest-now-decrypt-later exposure
    "mosca": 0.25,  # how far past Mosca's line we are (more negative margin -> higher)
    "deadline": 0.20,  # proximity of the disallowed-after deadline
    "classical_bits": 0.15,  # weaker classical strength -> easier / sooner to break
}

# Normalization references for the continuous components.
_MOSCA_MARGIN_SPAN_YEARS = 20.0  # margin clamped to [-span, +span] before scaling
_DEADLINE_SPAN_YEARS = 15.0  # deadline-distance clamped to [0, span] before scaling
_CLASSICAL_BITS_FLOOR = 80.0  # bits at/below this are treated as maximally urgent
_CLASSICAL_BITS_CEILING = 256.0  # bits at/above this contribute nothing


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def _hndl_component(asset: CryptoAsset) -> float:
    """1.0 for a vulnerable confidentiality primitive, else 0.0."""
    return 1.0 if (asset.quantum_vulnerable and asset.harvest_now_decrypt_later) else 0.0


def _mosca_component(mosca: MoscaAssessment | None) -> float:
    """Map Mosca margin to [0,1]: very negative margin -> 1.0, comfortable -> 0.0."""
    if mosca is None:
        return 0.0
    margin = _clamp(mosca.margin_years, -_MOSCA_MARGIN_SPAN_YEARS, _MOSCA_MARGIN_SPAN_YEARS)
    # margin = -span -> 1.0; margin = +span -> 0.0.
    return (_MOSCA_MARGIN_SPAN_YEARS - margin) / (2.0 * _MOSCA_MARGIN_SPAN_YEARS)


def _deadline_component(deadline_year: int | None, current_year: int) -> float:
    """Closer (or past) disallowed-after deadline -> closer to 1.0."""
    if deadline_year is None:
        return 0.0
    distance = _clamp(float(deadline_year - current_year), 0.0, _DEADLINE_SPAN_YEARS)
    return (_DEADLINE_SPAN_YEARS - distance) / _DEADLINE_SPAN_YEARS


def _classical_bits_component(classical_bits: int | None) -> float:
    """Lower classical strength -> higher urgency (linear between floor and ceiling)."""
    if classical_bits is None:
        return 0.0
    bits = _clamp(float(classical_bits), _CLASSICAL_BITS_FLOOR, _CLASSICAL_BITS_CEILING)
    return (_CLASSICAL_BITS_CEILING - bits) / (_CLASSICAL_BITS_CEILING - _CLASSICAL_BITS_FLOOR)


def _score(
    asset: CryptoAsset,
    *,
    mosca: MoscaAssessment | None,
    deadline_year: int | None,
    current_year: int,
) -> tuple[float, list[str]]:
    """Compute priority_score in [0,1] and a per-component explanation."""
    components = {
        "hndl": _hndl_component(asset),
        "mosca": _mosca_component(mosca),
        "deadline": _deadline_component(deadline_year, current_year),
        "classical_bits": _classical_bits_component(asset.classical_bits),
    }
    score = sum(_WEIGHTS[key] * value for key, value in components.items())
    score = round(_clamp(score, 0.0, 1.0), 4)
    explanation = [
        "priority_score blend: "
        + ", ".join(f"{key} {components[key]:.2f}x{_WEIGHTS[key]:g}" for key in _WEIGHTS)
        + f" = {score:g}."
    ]
    return score, explanation


def _classify(
    asset: CryptoAsset,
    *,
    mosca: MoscaAssessment | None,
    current_year: int,
) -> tuple[MigrationUrgency, list[str]]:
    """Decide urgency for one asset and explain the decision."""
    # NONE: already quantum-safe (PQ design or Grover-only-but-SAFE).
    if asset.quantum_threat is QuantumThreat.SAFE:
        return MigrationUrgency.NONE, ["Algorithm is quantum-safe; no migration required."]

    # LOW: Grover-weakened (e.g. AES-128, SHA-256) -- still adequate, monitor only.
    if asset.quantum_threat is QuantumThreat.WEAKENED:
        return (
            MigrationUrgency.LOW,
            [
                "Grover-weakened only (effective strength roughly halved); still adequate. "
                "Monitor and prefer a higher-strength parameter set where practical."
            ],
        )

    # From here the asset is quantum-vulnerable (Shor-broken).
    if asset.harvest_now_decrypt_later:
        deadline_soon = (
            asset.disallowed_after is not None
            and asset.disallowed_after <= current_year + IMMEDIATE_DEADLINE_HORIZON_YEARS
        )
        mosca_at_risk = mosca is not None and mosca.at_risk
        if mosca_at_risk or deadline_soon:
            reasons = ["Confidentiality / harvest-now-decrypt-later asset is already at risk."]
            if mosca_at_risk:
                reasons.append("Mosca's inequality trips: data cannot be kept secret for its life.")
            if deadline_soon:
                reasons.append(
                    f"Disallowed-after deadline {asset.disallowed_after} is within "
                    f"{IMMEDIATE_DEADLINE_HORIZON_YEARS} years of {current_year}."
                )
            return MigrationUrgency.IMMEDIATE, reasons
        return (
            MigrationUrgency.HIGH,
            [
                "Confidentiality / harvest-now-decrypt-later asset: recorded traffic is "
                "decryptable once a CRQC exists. Migration budget remains, but plan now."
            ],
        )

    # Quantum-vulnerable but not confidentiality -> signature / authenticity.
    return (
        MigrationUrgency.MEDIUM,
        [
            "Signature / authenticity primitive: forgery needs a CRQC at attack time, not "
            "retroactively, so recorded data is not exposed. Migrate before CRQC arrival."
        ],
    )


def _plan_item(
    asset: CryptoAsset,
    *,
    crqc_years: float,
    default_shelf_life_years: float,
    default_migration_years: float,
    current_year: int,
) -> MigrationItem:
    """Build the MigrationItem for one asset."""
    # Mosca assessment only for confidentiality / HNDL assets (recorded-traffic risk).
    mosca: MoscaAssessment | None = None
    if asset.quantum_vulnerable and asset.harvest_now_decrypt_later:
        mosca = assess_mosca(
            data_shelf_life_years=default_shelf_life_years,
            migration_years=default_migration_years,
            crqc_years=crqc_years,
        )

    urgency, urgency_reasons = _classify(asset, mosca=mosca, current_year=current_year)

    # Target replacements come from the registry; fall back to the asset's own list.
    targets: list[str] = []
    if asset.algorithm is not None:
        targets = list(registry_replacements(asset.algorithm))
    if not targets:
        targets = list(asset.recommended_replacement)

    # An explicit NIST IR 8547 disallowed-after date wins. Otherwise a
    # quantum-vulnerable (Shor-broken) asset that lacks one still inherits the
    # CNSA 2.0 exclusive-use year as its deadline. Quantum-safe (NONE) and
    # merely Grover-weakened (LOW, monitor-only) assets carry no hard deadline.
    if asset.disallowed_after is not None:
        deadline_year: int | None = asset.disallowed_after
    elif asset.quantum_vulnerable:
        deadline_year = CNSA_2_0_EXCLUSIVE_YEAR
    else:
        deadline_year = None

    score, score_reasons = _score(
        asset, mosca=mosca, deadline_year=deadline_year, current_year=current_year
    )

    rationale = [*urgency_reasons, *score_reasons]
    if targets:
        rationale.append(f"Recommended target algorithm(s): {targets}.")
    if deadline_year is not None:
        rationale.append(f"Migration deadline year: {deadline_year}.")

    return MigrationItem(
        asset=asset,
        urgency=urgency,
        priority_score=score,
        target_algorithms=targets,
        deadline_year=deadline_year,
        mosca=mosca,
        rationale=rationale,
    )


def _summary(items: list[MigrationItem], counts: dict[MigrationUrgency, int]) -> list[str]:
    """Build the human-readable summary lines for the plan."""
    lines: list[str] = []
    immediate = counts[MigrationUrgency.IMMEDIATE]
    if immediate:
        lines.append(f"{immediate} asset(s) require immediate migration.")
    else:
        lines.append("No assets require immediate migration.")

    high = counts[MigrationUrgency.HIGH]
    medium = counts[MigrationUrgency.MEDIUM]
    low = counts[MigrationUrgency.LOW]
    none = counts[MigrationUrgency.NONE]
    lines.append(
        f"Breakdown: {high} high, {medium} medium, {low} low (monitor), "
        f"{none} already quantum-safe."
    )

    deadlines = [item.deadline_year for item in items if item.deadline_year is not None]
    if deadlines:
        lines.append(f"Earliest disallowed deadline {min(deadlines)}.")

    return lines


def plan_migration(
    assets: list[CryptoAsset],
    *,
    crqc_years: float,
    default_shelf_life_years: float,
    default_migration_years: float,
    current_year: int = 2026,
) -> MigrationPlan:
    """Produce a prioritized post-quantum migration plan over a crypto inventory.

    Args:
        assets: the crypto inventory to plan over.
        crqc_years: Z -- estimated years until a CRQC exists (Mosca's inequality).
        default_shelf_life_years: X -- default confidentiality shelf-life applied
            to HNDL assets when no per-asset value is known.
        default_migration_years: Y -- default migration effort applied to HNDL
            assets when no per-asset value is known.
        current_year: the planning epoch (deterministic; not ``datetime.now``).

    Returns:
        A :class:`MigrationPlan` with items sorted by ``priority_score`` (descending,
        stable) and populated urgency counts plus a human summary.
    """
    items = [
        _plan_item(
            asset,
            crqc_years=crqc_years,
            default_shelf_life_years=default_shelf_life_years,
            default_migration_years=default_migration_years,
            current_year=current_year,
        )
        for asset in assets
    ]
    # Stable sort: ties preserve input order.
    items.sort(key=lambda item: item.priority_score, reverse=True)

    counts: dict[MigrationUrgency, int] = dict.fromkeys(MigrationUrgency, 0)
    for item in items:
        counts[item.urgency] += 1

    return MigrationPlan(
        items=items,
        total_assets=len(assets),
        immediate=counts[MigrationUrgency.IMMEDIATE],
        high=counts[MigrationUrgency.HIGH],
        medium=counts[MigrationUrgency.MEDIUM],
        low=counts[MigrationUrgency.LOW],
        already_safe=counts[MigrationUrgency.NONE],
        summary=_summary(items, counts),
    )
