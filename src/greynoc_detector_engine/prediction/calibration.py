from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class CalibrationAdjustment:
    probability: float
    reason: str | None = None


class ProbabilityCalibrator:
    """Transparent bucket calibrator backed by stored forecast outcomes."""

    def __init__(
        self,
        bucket_rates: dict[str, float] | None = None,
        *,
        sample_count: int = 0,
        blend: float = 0.25,
        min_bucket_count: int = 3,
    ) -> None:
        self.bucket_rates = dict(bucket_rates or {})
        self.sample_count = sample_count
        self.blend = max(0.0, min(1.0, blend))
        self.min_bucket_count = max(1, min_bucket_count)

    @classmethod
    def from_outcomes(
        cls,
        outcomes: list[dict[str, Any]],
        *,
        blend: float = 0.25,
        min_bucket_count: int = 3,
    ) -> ProbabilityCalibrator:
        values: dict[str, list[float]] = {}
        for row in outcomes:
            probability = float(row.get("forecast_probability", 0.0))
            outcome = float(row.get("verified_attack", 0))
            values.setdefault(bucket_for_probability(probability), []).append(outcome)
        rates = {
            bucket: sum(bucket_values) / len(bucket_values)
            for bucket, bucket_values in values.items()
            if len(bucket_values) >= min_bucket_count
        }
        return cls(
            rates,
            sample_count=len(outcomes),
            blend=blend,
            min_bucket_count=min_bucket_count,
        )

    def calibrate(self, probability: float) -> CalibrationAdjustment:
        bucket = bucket_for_probability(probability)
        observed_rate = self.bucket_rates.get(bucket)
        if observed_rate is None:
            return CalibrationAdjustment(probability=probability)
        adjusted = (1.0 - self.blend) * probability + self.blend * observed_rate
        return CalibrationAdjustment(
            probability=max(0.0, min(1.0, adjusted)),
            reason=(
                f"Calibration bucket {bucket}: blended probability "
                f"{probability:.3f} toward observed hit rate {observed_rate:.3f} "
                f"from {self.sample_count} stored outcomes."
            ),
        )


def bucket_for_probability(probability: float) -> str:
    if probability < 0.2:
        return "0.0-0.2"
    if probability < 0.4:
        return "0.2-0.4"
    if probability < 0.6:
        return "0.4-0.6"
    if probability < 0.8:
        return "0.6-0.8"
    return "0.8-1.0"


def precision_at_n(
    outcomes: list[dict[str, Any]],
    *,
    cutoffs: tuple[int, ...] = (5, 10, 20),
) -> dict[str, float]:
    ranked = sorted(
        outcomes,
        key=lambda row: float(row.get("forecast_probability", 0.0)),
        reverse=True,
    )
    metrics: dict[str, float] = {}
    for cutoff in cutoffs:
        subset = ranked[:cutoff]
        if not subset:
            continue
        hits = sum(1 for row in subset if bool(row.get("verified_attack", 0)))
        metrics[f"precision_at_{cutoff}"] = hits / len(subset)
    return metrics
