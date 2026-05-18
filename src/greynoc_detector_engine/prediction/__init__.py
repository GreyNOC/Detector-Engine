"""Forward-looking, OSINT-driven predictive engine.

This module consumes the reactive pipeline's outputs (threats, CVEs, KEV,
source items) along with OSINT enrichment (EPSS, ThreatFox, URLhaus,
Ransomwatch, threat-actor attribution, asset inventory, velocity baselines)
and produces a probabilistic attack forecast for each threat record.

All scoring is explainable: every probability ships with the named drivers
that produced it, their weights, and human-readable rationale lines.
"""

from greynoc_detector_engine.prediction.attack_forecast import AttackForecaster
from greynoc_detector_engine.prediction.exploit_timing import ExploitTimingModel
from greynoc_detector_engine.prediction.features import (
    PredictiveContext,
    PredictiveFeatureBuilder,
    PredictiveFeatures,
)
from greynoc_detector_engine.prediction.weaponization import WeaponizationModel

__all__ = [
    "AttackForecaster",
    "ExploitTimingModel",
    "PredictiveContext",
    "PredictiveFeatureBuilder",
    "PredictiveFeatures",
    "WeaponizationModel",
]
