"""Adapt fusion weights from analyst feedback.

We avoid the trap of "ML magic": this is a deliberately small, transparent
update rule that nudges weights up when a confirmed-true-positive threat had
high contribution from a given feature, and down when a confirmed-false-
positive threat had high contribution from that feature.

Steps:
  1. Pull threat records with both `attack_forecast` and analyst feedback.
  2. For each feedback row, look at the per-driver contribution that was
     used to produce the score.
  3. Apply a bounded delta: ``weight += learning_rate * sign * contribution``
     where ``sign`` is +1 for true positives and -1 for false positives.
  4. Renormalize and clamp.

Result: an updated fusion weight dict that the AttackForecaster can adopt.
"""

from __future__ import annotations

from collections.abc import Mapping

from greynoc_detector_engine.models.feedback import AnalystVerdict, ThreatFeedback
from greynoc_detector_engine.models.threat import ThreatRecord
from greynoc_detector_engine.prediction.attack_forecast import (
    DEFAULT_FUSION_WEIGHTS,
)

_TP = {AnalystVerdict.TRUE_POSITIVE}
_FP = {AnalystVerdict.FALSE_POSITIVE, AnalystVerdict.BENIGN_INTENT, AnalystVerdict.DUPLICATE}

# Per-step nudge cap so a single feedback row can't dominate.
_MAX_STEP = 0.05
# Absolute floor / ceiling for any weight.
_MIN_WEIGHT = 0.001
_MAX_WEIGHT = 0.5


class FeedbackTuner:
    """Apply analyst feedback to fusion weights deterministically."""

    def __init__(
        self,
        weights: Mapping[str, float] | None = None,
        *,
        learning_rate: float = 0.05,
    ) -> None:
        self.weights = dict(weights or DEFAULT_FUSION_WEIGHTS)
        self.learning_rate = max(0.0, min(1.0, learning_rate))

    def apply(
        self,
        feedback: list[ThreatFeedback],
        threats_by_id: Mapping[str, ThreatRecord],
    ) -> dict[str, float]:
        for fb in feedback:
            threat = threats_by_id.get(fb.threat_id)
            if threat is None or threat.attack_forecast is None:
                continue
            sign: int
            if fb.verdict in _TP:
                sign = +1
            elif fb.verdict in _FP:
                sign = -1
            else:
                continue
            for driver in threat.attack_forecast.drivers:
                if driver.name not in self.weights:
                    continue
                step = sign * self.learning_rate * driver.contribution
                # Cap per-step magnitude.
                step = max(-_MAX_STEP, min(_MAX_STEP, step))
                self.weights[driver.name] = max(
                    _MIN_WEIGHT,
                    min(_MAX_WEIGHT, self.weights[driver.name] + step),
                )
        # Renormalize to keep totals stable across runs.
        total = sum(self.weights.values()) or 1.0
        scale = sum(DEFAULT_FUSION_WEIGHTS.values()) / total
        return {k: round(max(_MIN_WEIGHT, v * scale), 6) for k, v in self.weights.items()}
