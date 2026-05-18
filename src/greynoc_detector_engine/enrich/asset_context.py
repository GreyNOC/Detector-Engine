from __future__ import annotations

import re
from pathlib import Path
from typing import Any, ClassVar

import yaml
from pydantic import BaseModel, ConfigDict, Field

from greynoc_detector_engine.models.asset import (
    AssetCriticality,
    AssetExposure,
    AssetRecord,
    TargetLikelihood,
)
from greynoc_detector_engine.models.threat import ThreatRecord


class AssetMatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset: AssetRecord
    matched_product: str
    overlap_score: float = Field(ge=0.0, le=1.0)


class AssetInventory:
    """Defender-supplied asset registry used to localize threats.

    The inventory is intentionally optional — when empty, predictions still
    work, just without target-likelihood signal.
    """

    def __init__(self, assets: list[AssetRecord] | None = None) -> None:
        self.assets: list[AssetRecord] = list(assets or [])
        self._assets_by_term: dict[str, list[AssetRecord]] = {}
        for asset in self.assets:
            for term in self._asset_terms(asset):
                self._assets_by_term.setdefault(term, []).append(asset)

    @classmethod
    def from_yaml(cls, path: Path) -> AssetInventory:
        if not path.exists():
            return cls()
        with path.open("r", encoding="utf-8") as handle:
            payload: dict[str, Any] = yaml.safe_load(handle) or {}
        raw = payload.get("assets") or []
        assets = [AssetRecord.model_validate(item) for item in raw if isinstance(item, dict)]
        return cls(assets=assets)

    def match_threat(self, threat: ThreatRecord) -> list[AssetMatch]:
        """Find inventory assets whose product/vendor overlaps with a threat."""

        matches: list[AssetMatch] = []
        threat_products = {p.lower() for p in threat.affected_products}
        candidates = self._candidate_assets(threat.affected_products)
        for asset in candidates:
            for product in threat.affected_products:
                if not self._matches(asset, product):
                    continue
                overlap = self._overlap_score(asset, product, threat_products)
                matches.append(
                    AssetMatch(
                        asset=asset,
                        matched_product=product,
                        overlap_score=overlap,
                    )
                )
                break
        return matches

    def _candidate_assets(self, products: list[str]) -> list[AssetRecord]:
        if not products:
            return []
        candidates: dict[str, AssetRecord] = {}
        for product in products:
            for term in self._normalize_terms(product):
                for asset in self._assets_by_term.get(term, []):
                    candidates[asset.asset_id] = asset
        if candidates:
            return list(candidates.values())
        return self.assets

    @classmethod
    def _asset_terms(cls, asset: AssetRecord) -> set[str]:
        values = [asset.vendor, asset.product, asset.name, *asset.tags]
        terms: set[str] = set()
        for value in values:
            if value:
                terms.update(cls._normalize_terms(value))
        return terms

    @staticmethod
    def _normalize_terms(value: str) -> set[str]:
        return {part for part in re.split(r"[^a-z0-9]+", value.lower()) if len(part) >= 3}

    @staticmethod
    def _matches(asset: AssetRecord, product: str) -> bool:
        product_l = product.lower()
        candidates = [c for c in (asset.product, asset.vendor, asset.name) if c]
        return any(c.lower() in product_l or product_l in c.lower() for c in candidates)

    @staticmethod
    def _overlap_score(asset: AssetRecord, product: str, all_products: set[str]) -> float:
        score = 0.5
        if asset.vendor and asset.vendor.lower() in product.lower():
            score += 0.2
        if asset.product and asset.product.lower() in product.lower():
            score += 0.2
        if len(all_products) > 1:
            score += 0.1
        return min(1.0, score)


class TargetLikelihoodScorer:
    """Estimate how likely each of our assets is to be hit by a given threat."""

    _EXPOSURE_WEIGHT: ClassVar[dict[AssetExposure, float]] = {
        AssetExposure.INTERNAL: 0.25,
        AssetExposure.DMZ: 0.55,
        AssetExposure.INTERNET_FACING: 0.9,
        AssetExposure.CLOUD_PUBLIC: 0.85,
    }
    _CRIT_WEIGHT: ClassVar[dict[AssetCriticality, float]] = {
        AssetCriticality.LOW: 0.2,
        AssetCriticality.MEDIUM: 0.5,
        AssetCriticality.HIGH: 0.8,
        AssetCriticality.CROWN_JEWEL: 1.0,
    }

    def score(self, threat: ThreatRecord, matches: list[AssetMatch]) -> list[TargetLikelihood]:
        out: list[TargetLikelihood] = []
        if not matches:
            return out
        base_probability = 0.5
        if threat.attack_forecast is not None:
            base_probability = threat.attack_forecast.attack_probability
        elif threat.predictive_score is not None:
            base_probability = threat.predictive_score.numeric_score / 100.0

        for match in matches:
            exposure = self._EXPOSURE_WEIGHT[match.asset.exposure]
            crit = self._CRIT_WEIGHT[match.asset.criticality]
            sector_alignment = (
                0.2
                if (
                    match.asset.sector
                    and match.asset.sector.lower() in {s.lower() for s in threat.sectors_at_risk}
                )
                else 0.0
            )
            likelihood = min(
                1.0,
                base_probability
                * (0.4 + 0.4 * exposure + 0.2 * sector_alignment)
                * (0.5 + 0.5 * match.overlap_score),
            )
            blast_radius = min(1.0, 0.5 + 0.5 * crit)
            reasons = [
                f"Asset exposure '{match.asset.exposure.value}' weight {exposure:.2f}.",
                f"Asset criticality '{match.asset.criticality.value}' weight {crit:.2f}.",
                f"Product overlap on '{match.matched_product}' score {match.overlap_score:.2f}.",
            ]
            if sector_alignment:
                reasons.append("Sector aligns with sectors-at-risk for this threat.")
            out.append(
                TargetLikelihood(
                    asset_id=match.asset.asset_id,
                    threat_id=threat.threat_id,
                    likelihood=round(likelihood, 4),
                    blast_radius=round(blast_radius, 4),
                    reasons=reasons,
                )
            )
        return out
