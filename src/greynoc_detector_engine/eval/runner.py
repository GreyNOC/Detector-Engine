"""Drive the forecast evaluation harness over a labeled corpus.

Three operations, all offline and pure-Python:

  * :func:`evaluate_forecast_corpus` -- the headline metric report (ROC-AUC,
    TPR@FPR, F1, ECE/Brier) for a forecaster's scores vs. realized outcomes.
  * :func:`fit_forecast_calibration` -- Platt-scale the raw fused score and
    report whether calibration helped.
  * :func:`learn_fusion_weights` -- fit glass-box per-driver weights from the
    ``drivers`` maps in the corpus, producing a drop-in suggestion for the
    ``predictive_fusion_weights`` block of ``scoring.yaml``.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from greynoc_detector_engine.eval.corpus import ForecastExample
from greynoc_detector_engine.eval.logistic import fit_logistic
from greynoc_detector_engine.eval.metrics import EvaluationReport, evaluate_scores, roc_auc
from greynoc_detector_engine.eval.platt import CalibrationResult, fit_platt

_SCORES_OUT_OF_RANGE_NOTE = (
    "scores fall outside [0,1]; ECE/Brier are reported as null (calibrate first)."
)


def evaluate_forecast_corpus(
    examples: Sequence[ForecastExample],
    *,
    name: str = "attack_forecast",
    threshold: float = 0.5,
) -> EvaluationReport:
    """Headline metric report for ``example.score`` vs. ``example.label``."""
    scores = [example.score for example in examples]
    labels = [example.label for example in examples]
    notes: list[str] = []
    if scores and any(s < 0.0 or s > 1.0 for s in scores):
        notes.append(_SCORES_OUT_OF_RANGE_NOTE)
    return evaluate_scores(name, scores, labels, threshold=threshold, notes=notes)


def fit_forecast_calibration(
    examples: Sequence[ForecastExample], *, l2: float = 1.0
) -> CalibrationResult:
    """Fit Platt scaling on the corpus's raw scores."""
    scores = [example.score for example in examples]
    labels = [example.label for example in examples]
    return fit_platt(scores, labels, l2=l2)


@dataclass
class LearnedFusionWeights:
    """Glass-box per-driver weights learned from realized outcomes."""

    bias: float
    raw_coefficients: dict[str, float]
    suggested_weights: dict[str, float]
    trained_on: int
    train_auc: float | None
    l2: float

    def as_dict(self) -> dict[str, object]:
        return {
            "bias": round(self.bias, 6),
            "raw_coefficients": {k: round(v, 6) for k, v in self.raw_coefficients.items()},
            "suggested_predictive_fusion_weights": {
                k: round(v, 6) for k, v in self.suggested_weights.items()
            },
            "trained_on": self.trained_on,
            "train_auc": None if self.train_auc is None else round(self.train_auc, 4),
            "l2": self.l2,
            "_note": (
                "Learned per-driver weights. train_auc is OPTIMISTIC (no held-out "
                "split); refit on a real, held-out-evaluated outcome corpus before "
                "trusting these. raw_coefficients are the honest glass-box logistic "
                "fit (may be negative); suggested_predictive_fusion_weights clamps to "
                ">=0 and renormalizes for direct paste into scoring.yaml."
            ),
        }


def _driver_feature_space(examples: Sequence[ForecastExample]) -> list[str]:
    seen: set[str] = set()
    for example in examples:
        seen.update(example.drivers)
    return sorted(seen)


def learn_fusion_weights(
    examples: Sequence[ForecastExample], *, l2: float = 2.0
) -> LearnedFusionWeights:
    """Fit a logistic over the corpus's per-driver contributions.

    Each feature is one driver name; its value for an example is that driver's
    contribution (0.0 if the driver did not fire). The feature space is the
    sorted union of every driver seen in the corpus, so coefficients map
    one-to-one onto driver names -- the same names used in ``scoring.yaml``.
    """
    feature_names = _driver_feature_space(examples)
    if not feature_names:
        raise ValueError("no 'drivers' present in the corpus; nothing to learn")
    rows = [[example.drivers.get(name, 0.0) for name in feature_names] for example in examples]
    labels = [example.label for example in examples]
    model = fit_logistic(rows, labels, feature_names=feature_names, l2=l2)
    raw = dict(zip(feature_names, model.coefficients, strict=True))

    # Clamp negatives to zero and renormalize to sum 1.0 so the result can be
    # pasted straight into scoring.yaml's predictive_fusion_weights (which the
    # forecaster normalizes by total weight anyway).
    positive = {name: max(0.0, coef) for name, coef in raw.items()}
    total = sum(positive.values())
    suggested = (
        {name: value / total for name, value in positive.items()}
        if total > 0
        else dict.fromkeys(feature_names, 1.0 / len(feature_names))
    )

    train_scores = [model.predict_proba(row) for row in rows]
    return LearnedFusionWeights(
        bias=model.bias,
        raw_coefficients=raw,
        suggested_weights=suggested,
        trained_on=len(examples),
        train_auc=roc_auc(train_scores, labels),
        l2=l2,
    )
