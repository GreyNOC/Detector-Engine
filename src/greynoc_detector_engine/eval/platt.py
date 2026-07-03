"""Turn raw forecast scores into calibrated probabilities (Platt scaling).

The runtime forecaster already blends in an outcome-bucket calibrator
(:class:`greynoc_detector_engine.prediction.calibration.ProbabilityCalibrator`).
This module is the *offline* counterpart: given a labeled corpus, fit a smooth
logistic map from the raw fused score to a probability and report whether
calibration actually helped (ECE + Brier before/after). It is a measurement and
tuning tool, never on the request path.

Adapted from GN-SLOP-DETECTION ``app/eval/calibrate.py`` (the perplexity-mapping
variant, specific to a text model, is intentionally omitted here).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from greynoc_detector_engine.eval.logistic import LogisticModel, fit_logistic
from greynoc_detector_engine.eval.metrics import brier_score, expected_calibration_error


@dataclass
class CalibrationResult:
    model: LogisticModel
    ece_before: float | None
    ece_after: float | None
    brier_before: float | None
    brier_after: float | None
    n: int

    def as_dict(self) -> dict[str, object]:
        return {
            "model": self.model.as_dict(),
            "n": self.n,
            "ece_before": None if self.ece_before is None else round(self.ece_before, 4),
            "ece_after": None if self.ece_after is None else round(self.ece_after, 4),
            "brier_before": None if self.brier_before is None else round(self.brier_before, 4),
            "brier_after": None if self.brier_after is None else round(self.brier_after, 4),
        }


def fit_platt(
    scores: Sequence[float], labels: Sequence[int], *, l2: float = 1.0
) -> CalibrationResult:
    """Platt scaling: logistic map from a single raw score to a probability."""
    if len(scores) != len(labels):
        raise ValueError("scores/labels length mismatch")
    features = [[float(s)] for s in scores]
    model = fit_logistic(features, labels, feature_names=["score"], l2=l2)
    calibrated = [model.predict_proba([float(s)]) for s in scores]
    # ECE/Brier on the raw scores is only meaningful if they're already in
    # [0,1]; the helpers return None otherwise, which we surface honestly.
    return CalibrationResult(
        model=model,
        ece_before=expected_calibration_error(scores, labels),
        ece_after=expected_calibration_error(calibrated, labels),
        brier_before=brier_score(scores, labels),
        brier_after=brier_score(calibrated, labels),
        n=len(scores),
    )
