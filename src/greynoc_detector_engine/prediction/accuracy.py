"""Track forecast accuracy and surface calibration drift.

Each forecast we emit can be marked later as either *verified true* (an
attack did happen against this threat within the horizon) or *verified
false*. Over time we accumulate (forecast_probability, outcome) pairs and
compute:

  * Brier score — mean squared error between probability and outcome.
  * Hit rate per probability bucket — does "0.7" actually mean roughly 70%?
  * Hit rate per horizon — are IMMINENT predictions calibrated?

This is the foundation of "the engine learns from being wrong". Lower
Brier = better calibration.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class CalibrationBucket(BaseModel):
    model_config = ConfigDict(extra="forbid")

    bucket: str
    count: int = 0
    mean_predicted: float = 0.0
    mean_outcome: float = 0.0


class AccuracyReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sample_count: int
    brier_score: float = Field(ge=0.0, le=1.0)
    accuracy_at_50: float = Field(ge=0.0, le=1.0)
    buckets: list[CalibrationBucket] = Field(default_factory=list)
    by_horizon: dict[str, CalibrationBucket] = Field(default_factory=dict)


def compute_accuracy(outcomes: list[dict[str, Any]]) -> AccuracyReport:
    """Compute calibration metrics from stored ``forecast_outcomes`` rows."""
    n = len(outcomes)
    if n == 0:
        return AccuracyReport(
            sample_count=0,
            brier_score=0.0,
            accuracy_at_50=0.0,
        )

    brier_sum = 0.0
    correct_at_50 = 0
    bucket_predictions: dict[str, list[float]] = defaultdict(list)
    bucket_outcomes: dict[str, list[float]] = defaultdict(list)
    horizon_predictions: dict[str, list[float]] = defaultdict(list)
    horizon_outcomes: dict[str, list[float]] = defaultdict(list)

    for row in outcomes:
        p = float(row.get("forecast_probability", 0.0))
        y = float(row.get("verified_attack", 0))
        horizon = str(row.get("forecast_horizon", "unknown"))
        brier_sum += (p - y) ** 2
        if (p >= 0.5) == (y >= 0.5):
            correct_at_50 += 1
        bkt = _bucket(p)
        bucket_predictions[bkt].append(p)
        bucket_outcomes[bkt].append(y)
        horizon_predictions[horizon].append(p)
        horizon_outcomes[horizon].append(y)

    buckets: list[CalibrationBucket] = []
    for bkt in ("0.0-0.2", "0.2-0.4", "0.4-0.6", "0.6-0.8", "0.8-1.0"):
        preds = bucket_predictions.get(bkt, [])
        if not preds:
            continue
        outs = bucket_outcomes.get(bkt, [])
        buckets.append(
            CalibrationBucket(
                bucket=bkt,
                count=len(preds),
                mean_predicted=sum(preds) / len(preds),
                mean_outcome=sum(outs) / max(1, len(outs)),
            )
        )

    by_horizon: dict[str, CalibrationBucket] = {}
    for horizon, preds in horizon_predictions.items():
        outs = horizon_outcomes.get(horizon, [])
        by_horizon[horizon] = CalibrationBucket(
            bucket=horizon,
            count=len(preds),
            mean_predicted=sum(preds) / len(preds),
            mean_outcome=sum(outs) / max(1, len(outs)),
        )

    return AccuracyReport(
        sample_count=n,
        brier_score=brier_sum / n,
        accuracy_at_50=correct_at_50 / n,
        buckets=buckets,
        by_horizon=by_horizon,
    )


def _bucket(p: float) -> str:
    if p < 0.2:
        return "0.0-0.2"
    if p < 0.4:
        return "0.2-0.4"
    if p < 0.6:
        return "0.4-0.6"
    if p < 0.8:
        return "0.6-0.8"
    return "0.8-1.0"
