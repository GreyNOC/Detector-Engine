from __future__ import annotations

from greynoc_detector_engine.models.prediction import (
    AttackForecast,
    ConfidenceBand,
    PredictionDriver,
)
from greynoc_detector_engine.prediction.calibration import ProbabilityCalibrator
from greynoc_detector_engine.prediction.exploit_timing import (
    ExploitTimingModel,
    TimingEstimate,
)
from greynoc_detector_engine.prediction.features import (
    PredictiveContext,
    PredictiveFeatureBuilder,
    PredictiveFeatures,
)
from greynoc_detector_engine.prediction.weaponization import (
    WeaponizationEstimate,
    WeaponizationModel,
)
from greynoc_detector_engine.utils.hashing import canonical_json_hash

# Fusion weights for the final probability — exposed in scoring.yaml.
DEFAULT_FUSION_WEIGHTS: dict[str, float] = {
    "epss_probability": 0.22,
    "kev_listed": 0.18,
    "local_intrusion_pressure": 0.15,
    "public_exploit_availability": 0.11,
    "chatter_velocity": 0.09,
    "ransomware_proximity": 0.07,
    "active_campaign": 0.06,
    "actor_activity": 0.05,
    "osint_ioc_corroboration": 0.04,
    "trusted_source_corroboration": 0.02,
    "independent_source_diversity": 0.01,
    "cvss_pressure": 0.005,
    "ai_attack_relevance": 0.005,
}


class AttackForecaster:
    """Top-level orchestrator: features -> timing + weaponization -> forecast."""

    def __init__(
        self,
        *,
        feature_builder: PredictiveFeatureBuilder | None = None,
        timing: ExploitTimingModel | None = None,
        weaponization: WeaponizationModel | None = None,
        fusion_weights: dict[str, float] | None = None,
        calibration: ProbabilityCalibrator | None = None,
        model_version: str = "horizon-1.1",
        config_hash: str | None = None,
    ) -> None:
        self.feature_builder = feature_builder or PredictiveFeatureBuilder()
        self.timing = timing or ExploitTimingModel()
        self.weaponization = weaponization or WeaponizationModel()
        self.fusion_weights = fusion_weights or DEFAULT_FUSION_WEIGHTS
        self.calibration = calibration
        self.config_hash = config_hash or canonical_json_hash(
            {"fusion_weights": self.fusion_weights},
            length=12,
        )
        self.model_version = f"{model_version}+cfg-{self.config_hash[:8]}"

    @classmethod
    def from_config(
        cls,
        *,
        scoring_config: dict[str, object],
        horizon_config: dict[str, object],
        feature_builder: PredictiveFeatureBuilder | None = None,
        calibration: ProbabilityCalibrator | None = None,
    ) -> AttackForecaster:
        raw_weights = scoring_config.get("predictive_fusion_weights", DEFAULT_FUSION_WEIGHTS)
        weights = (
            {str(key): float(value) for key, value in raw_weights.items()}
            if isinstance(raw_weights, dict)
            else DEFAULT_FUSION_WEIGHTS
        )
        config_hash = canonical_json_hash(
            {
                "scoring": scoring_config,
                "attack_horizon": horizon_config,
                "calibration_samples": calibration.sample_count if calibration else 0,
            },
            length=12,
        )
        horizon_version = horizon_config.get("version", "1")
        return cls(
            feature_builder=feature_builder,
            timing=ExploitTimingModel.from_config(horizon_config),
            fusion_weights=weights,
            calibration=calibration,
            model_version=f"horizon-{horizon_version}",
            config_hash=config_hash,
        )

    def forecast(self, ctx: PredictiveContext) -> AttackForecast:
        features = self.feature_builder.build(ctx)
        timing_estimate = self.timing.estimate(features)
        weapon_estimate = self.weaponization.estimate(features)

        attack_probability, drivers = self._fuse(features, weapon_estimate)
        calibration_reason: str | None = None
        if self.calibration is not None:
            adjusted = self.calibration.calibrate(attack_probability)
            attack_probability = adjusted.probability
            calibration_reason = adjusted.reason
        confidence = self._confidence(features, ctx)
        reasons = self._reasons(features, timing_estimate, weapon_estimate, attack_probability)
        if calibration_reason is not None:
            reasons.append(calibration_reason)
        return AttackForecast(
            attack_probability=round(attack_probability, 4),
            horizon=timing_estimate.horizon,
            horizon_days_p50=timing_estimate.p50_days,
            horizon_days_p90=timing_estimate.p90_days,
            confidence=confidence,
            drivers=drivers,
            reasons=reasons,
            osint_signal_count=sum(
                [
                    features.epss_probability > 0,
                    features.kev_listed > 0,
                    features.public_exploit_availability > 0,
                    features.ransomware_proximity > 0,
                    features.actor_activity > 0,
                    features.active_campaign > 0,
                    features.osint_ioc_corroboration > 0,
                    features.chatter_velocity > 0,
                ]
            ),
            independent_corroborations=len({ref.source for ref in ctx.threat.source_references}),
            model_version=self.model_version,
        )

    def _fuse(
        self,
        features: PredictiveFeatures,
        weapon: WeaponizationEstimate,
    ) -> tuple[float, list[PredictionDriver]]:
        feat = features.as_dict()
        weighted = 0.0
        total_weight = sum(self.fusion_weights.values())
        drivers: list[PredictionDriver] = []
        for name, weight in self.fusion_weights.items():
            value = float(feat.get(name, 0.0))
            contribution = (weight / total_weight) * value
            weighted += contribution
            if value > 0:
                drivers.append(
                    PredictionDriver(
                        name=name,
                        weight=round(weight, 4),
                        value=round(value, 4),
                        contribution=round(contribution, 4),
                        rationale=self._driver_rationale(name, value),
                    )
                )

        # Blend with weaponization probability so a credible weaponization path
        # cannot be drowned by noisy reactive signals.
        fused = 0.65 * weighted + 0.35 * weapon.probability
        drivers.append(
            PredictionDriver(
                name="weaponization_blend",
                weight=0.35,
                value=round(weapon.probability, 4),
                contribution=round(0.35 * weapon.probability, 4),
                rationale="Logistic weaponization estimate blended with reactive features.",
            )
        )
        return min(1.0, max(0.0, fused)), drivers

    @staticmethod
    def _driver_rationale(name: str, value: float) -> str:
        humanized = name.replace("_", " ")
        return f"{humanized} = {value:.3f} (normalized 0..1)."

    @staticmethod
    def _confidence(features: PredictiveFeatures, ctx: PredictiveContext) -> ConfidenceBand:
        # More independent sources + EPSS available + KEV/exploit corroboration => higher
        score = 0
        if features.independent_source_diversity >= 0.4:
            score += 1
        if features.epss_probability > 0:
            score += 1
        if features.kev_listed > 0 or features.public_exploit_availability >= 0.5:
            score += 1
        if features.osint_ioc_corroboration >= 0.3:
            score += 1
        if features.recency >= 0.6:
            score += 1
        if score >= 4:
            return ConfidenceBand.HIGH
        if score >= 2:
            return ConfidenceBand.MEDIUM
        return ConfidenceBand.LOW

    @staticmethod
    def _reasons(
        features: PredictiveFeatures,
        timing: TimingEstimate,
        weapon: WeaponizationEstimate,
        probability: float,
    ) -> list[str]:
        reasons: list[str] = []
        if features.kev_listed >= 1.0:
            reasons.append("CISA KEV confirms exploitation; near-term attack expected.")
        if features.epss_probability >= 0.3:
            reasons.append(
                f"EPSS prior {features.epss_probability:.2f} is materially above background."
            )
        if features.public_exploit_availability >= 0.5:
            reasons.append("Multiple public exploit references reduce attacker friction.")
        if features.chatter_velocity >= 0.5:
            reasons.append(
                "Short-window chatter velocity is anomalously high vs. long-window baseline."
            )
        if features.ransomware_proximity >= 0.5:
            reasons.append("Ransomware proximity raises operational urgency.")
        if features.actor_activity >= 0.5:
            reasons.append("Known threat-actor signals are co-mentioned with this threat.")
        if features.active_campaign >= 1.0:
            reasons.append("Threat is part of an actively-tracked campaign cluster.")
        if features.osint_ioc_corroboration >= 0.3:
            reasons.append("OSINT IOC feeds corroborate observed indicators.")
        reasons.extend(timing.reasoning)
        reasons.append(f"Weaponization probability estimate {weapon.probability:.2f}.")
        reasons.append(f"Fused attack probability {probability:.2f}.")
        return reasons
