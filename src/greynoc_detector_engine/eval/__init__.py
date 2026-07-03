"""Offline evaluation harness for the predictive / scoring layer.

Detection quality is measurable, not vibes. This package scores the engine's
``AttackForecast`` probabilities against a labeled corpus of realized outcomes
and reports the metrics the detection literature actually uses -- ROC-AUC,
TPR at a fixed low false-positive rate, F1, and calibration error (ECE/Brier).
It also fits Platt calibration and learns glass-box per-driver fusion weights.

It is a pure-Python offline tool (no numpy / sklearn) and is **never** invoked
at request time -- forecasting in production uses the hand-tuned and
outcome-calibrated path in :mod:`greynoc_detector_engine.prediction`.

The metric and logistic implementations were adapted from the GreyNOC
GN-SLOP-DETECTION ``app/eval`` harness and retargeted from text-slop detection
onto attack forecasting (positive class == "threat was actually exploited").
"""

from __future__ import annotations

from greynoc_detector_engine.eval.corpus import (
    ForecastCorpusStats,
    ForecastExample,
    load_forecast_corpus,
)
from greynoc_detector_engine.eval.metrics import EvaluationReport, evaluate_scores
from greynoc_detector_engine.eval.runner import (
    LearnedFusionWeights,
    evaluate_forecast_corpus,
    fit_forecast_calibration,
    learn_fusion_weights,
)

__all__ = [
    "EvaluationReport",
    "ForecastCorpusStats",
    "ForecastExample",
    "LearnedFusionWeights",
    "evaluate_forecast_corpus",
    "evaluate_scores",
    "fit_forecast_calibration",
    "learn_fusion_weights",
    "load_forecast_corpus",
]
