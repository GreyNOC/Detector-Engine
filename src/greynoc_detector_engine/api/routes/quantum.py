"""Post-quantum threat-assessment endpoints.

Stateless, read-only analysis: score threat text for quantum exposure, evaluate
Mosca's inequality, assess a crypto inventory, build a migration plan, and emit a
CBOM. All inputs are supplied in the request body; nothing here mutates state.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict, Field

from greynoc_detector_engine.analysis import cbom as cbom_mod
from greynoc_detector_engine.analysis import crypto_inventory as ci
from greynoc_detector_engine.analysis import pqc_migration as pm
from greynoc_detector_engine.analysis.mosca import assess_mosca
from greynoc_detector_engine.analysis.quantum_risk import QuantumRiskClassifier
from greynoc_detector_engine.config.settings import get_settings

router = APIRouter()


class TextScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str
    products: list[str] = Field(default_factory=list)


class MoscaRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data_shelf_life_years: float = Field(ge=0)
    migration_years: float = Field(ge=0)
    crqc_years: float = Field(ge=0)


class InventoryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assets: list[dict[str, Any]]
    crqc_years: float | None = Field(default=None, ge=0)
    default_shelf_life_years: float | None = Field(default=None, ge=0)
    default_migration_years: float | None = Field(default=None, ge=0)
    current_year: int = 2026


def _horizons(req: InventoryRequest) -> tuple[float, float, float]:
    settings = get_settings()
    return (
        req.crqc_years if req.crqc_years is not None else settings.crqc_estimate_years,
        req.default_shelf_life_years
        if req.default_shelf_life_years is not None
        else settings.default_data_shelf_life_years,
        req.default_migration_years
        if req.default_migration_years is not None
        else settings.default_migration_years,
    )


@router.post("/quantum/scan")
def scan_text(request: TextScanRequest) -> dict[str, object]:
    """Assess threat text for quantum-vulnerable crypto and HNDL exposure."""
    assessment = QuantumRiskClassifier().assess(request.text, request.products)
    return assessment.model_dump(mode="json")


@router.post("/quantum/mosca")
def mosca(request: MoscaRequest) -> dict[str, object]:
    """Evaluate Mosca's inequality (X + Y >= Z => already at risk)."""
    result = assess_mosca(
        data_shelf_life_years=request.data_shelf_life_years,
        migration_years=request.migration_years,
        crqc_years=request.crqc_years,
    )
    return result.model_dump(mode="json")


@router.post("/quantum/inventory")
def assess_inventory(request: InventoryRequest) -> dict[str, object]:
    """Assess a crypto inventory's quantum posture with per-asset Mosca."""
    crqc, shelf, migration = _horizons(request)
    assets, summary, mosca_by_asset = ci.assess_inventory(
        request.assets,
        crqc_years=crqc,
        default_shelf_life_years=shelf,
        default_migration_years=migration,
    )
    return {
        "summary": summary.model_dump(mode="json"),
        "assets": [a.model_dump(mode="json") for a in assets],
        "mosca": {k: v.model_dump(mode="json") for k, v in mosca_by_asset.items()},
    }


@router.post("/quantum/plan")
def migration_plan(request: InventoryRequest) -> dict[str, object]:
    """Build a prioritized post-quantum migration plan for an inventory."""
    crqc, shelf, migration = _horizons(request)
    assets, _summary, _mosca = ci.assess_inventory(
        request.assets,
        crqc_years=crqc,
        default_shelf_life_years=shelf,
        default_migration_years=migration,
    )
    plan = pm.plan_migration(
        assets,
        crqc_years=crqc,
        default_shelf_life_years=shelf,
        default_migration_years=migration,
        current_year=request.current_year,
    )
    return plan.model_dump(mode="json")


@router.post("/quantum/cbom")
def generate_cbom(request: InventoryRequest) -> dict[str, object]:
    """Emit a CycloneDX 1.6 Cryptographic Bill of Materials for an inventory."""
    crqc, shelf, migration = _horizons(request)
    assets, _summary, _mosca = ci.assess_inventory(
        request.assets,
        crqc_years=crqc,
        default_shelf_life_years=shelf,
        default_migration_years=migration,
    )
    bom = cbom_mod.generate_cbom(assets)
    return bom.model_dump(mode="json", by_alias=True)
