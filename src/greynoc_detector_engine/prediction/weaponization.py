from __future__ import annotations

import math
from typing import ClassVar

from pydantic import BaseModel, ConfigDict

from greynoc_detector_engine.prediction.features import PredictiveFeatures


class WeaponizationEstimate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    probability: float
    reasoning: list[str]


class WeaponizationModel:
    """Probability that *someone* operationalizes the threat into an attack tool.

    Weaponization is distinct from exploitation: a public PoC may exist, but
    only a fraction become part of malware kits, RaaS playbooks, or red-team
    toolkits in the wild. The signal mix that drives weaponization differs
    from time-to-exploit: vendor emergency language and ransomware signals
    weigh heavier; pure CVSS pressure weighs less.
    """

    # Logistic regression-style weights, tuned by inspection (no training data).
    _WEIGHTS: ClassVar[dict[str, float]] = {
        "epss_probability": 1.4,
        "kev_listed": 1.6,
        "public_exploit_availability": 1.2,
        "ransomware_proximity": 1.5,
        "actor_activity": 0.9,
        "active_campaign": 1.0,
        "osint_ioc_corroboration": 1.0,
        "local_intrusion_pressure": 1.3,
        "chatter_velocity": 0.6,
        "cvss_pressure": 0.4,
        "ai_attack_relevance": 0.3,
    }
    _BIAS: ClassVar[float] = -2.0

    def estimate(self, features: PredictiveFeatures) -> WeaponizationEstimate:
        feature_dict = features.as_dict()
        logit = self._BIAS
        reasoning: list[str] = []
        for name, weight in self._WEIGHTS.items():
            value = float(feature_dict.get(name, 0.0))
            if value <= 0:
                continue
            contribution = weight * value
            logit += contribution
            reasoning.append(
                f"{name} (w={weight:.2f}, x={value:.3f}) contributes {contribution:+.3f}."
            )
        probability = 1.0 / (1.0 + math.exp(-logit))
        reasoning.append(f"Logit {logit:.3f} -> probability {probability:.3f}.")
        return WeaponizationEstimate(
            probability=round(probability, 4),
            reasoning=reasoning,
        )
