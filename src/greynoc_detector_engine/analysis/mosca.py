"""Mosca's inequality -- are we already too late to protect this data?

Michele Mosca's theorem frames the harvest-now-decrypt-later (HNDL) problem with
three horizons:

  * **X** -- how many years the data must stay confidential (security shelf-life),
  * **Y** -- how many years a safe migration to post-quantum crypto will take,
  * **Z** -- how many years until a cryptographically-relevant quantum computer
    (CRQC) can break the protection.

If ``X + Y > Z`` you cannot keep the data secret for its required lifetime -- you
have already, in effect, run out of time. The formal statement uses strict ``>``;
this module uses ``>=`` as the conservative planning boundary (the worst case is
exactly on the line). The migration *budget* before exposure is ``Z - X``.

This is a glass-box arithmetic helper -- no model, no network. Shared by the
crypto-inventory scanner and the migration planner so the calculation lives in
exactly one place.
"""

from __future__ import annotations

from greynoc_detector_engine.models.crypto import MoscaAssessment


def assess_mosca(
    *,
    data_shelf_life_years: float,
    migration_years: float,
    crqc_years: float,
) -> MoscaAssessment:
    """Evaluate Mosca's inequality for one data class / asset.

    All arguments are in years and must be non-negative. ``crqc_years`` is the
    estimated time until a CRQC exists (Z); the smaller it is, the sooner the
    exposure.
    """
    for label, value in (
        ("data_shelf_life_years", data_shelf_life_years),
        ("migration_years", migration_years),
        ("crqc_years", crqc_years),
    ):
        if value < 0:
            raise ValueError(f"{label} must be non-negative, got {value!r}")

    exposure = data_shelf_life_years + migration_years
    margin = crqc_years - exposure
    at_risk = exposure >= crqc_years
    max_migration = crqc_years - data_shelf_life_years

    rationale: list[str] = [
        f"X (shelf-life) = {data_shelf_life_years:g}y + Y (migration) = "
        f"{migration_years:g}y = {exposure:g}y vs Z (CRQC) = {crqc_years:g}y."
    ]
    if at_risk:
        rationale.append(
            f"X + Y >= Z by {abs(margin):g}y: data encrypted today cannot be kept "
            "secret for its required lifetime -- harvest-now-decrypt-later exposure "
            "exists now. Migrate immediately."
        )
    else:
        rationale.append(
            f"X + Y < Z with {margin:g}y of margin; migration budget before exposure "
            f"is Z - X = {max_migration:g}y."
        )
    if max_migration < migration_years:
        rationale.append(
            f"Planned migration ({migration_years:g}y) exceeds the available budget "
            f"({max_migration:g}y); the migration itself will not finish in time."
        )

    return MoscaAssessment(
        data_shelf_life_years=data_shelf_life_years,
        migration_years=migration_years,
        crqc_years=crqc_years,
        at_risk=at_risk,
        margin_years=margin,
        max_migration_years=max_migration,
        rationale=rationale,
    )
