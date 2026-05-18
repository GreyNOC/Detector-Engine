from __future__ import annotations

from greynoc_detector_engine.models.prediction import AttackForecast
from greynoc_detector_engine.models.scoring import ScoreResult, score_label


class PredictiveScorer:
    """Convert an `AttackForecast` into the engine's standard `ScoreResult`.

    Keeps everything that downstream code (storage, API, narratives) sees
    consistent: the predictive layer never invents a new score schema.
    """

    def score(self, forecast: AttackForecast) -> ScoreResult:
        numeric = round(min(100.0, forecast.attack_probability * 100.0), 2)
        signals: dict[str, object] = {
            "horizon": forecast.horizon.value,
            "horizon_days_p50": forecast.horizon_days_p50,
            "horizon_days_p90": forecast.horizon_days_p90,
            "confidence": forecast.confidence.value,
            "osint_signal_count": forecast.osint_signal_count,
            "independent_corroborations": forecast.independent_corroborations,
            "model_version": forecast.model_version,
            "drivers": [d.model_dump(mode="json") for d in forecast.drivers],
        }
        return ScoreResult(
            score=numeric,
            label=score_label(numeric),
            reasons=forecast.reasons,
            contributing_signals=signals,
        )
