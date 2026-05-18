from __future__ import annotations

from greynoc_detector_engine.models.cve import CVERecord
from greynoc_detector_engine.models.kev import KEVRecord
from greynoc_detector_engine.models.scoring import ScoreResult, score_label
from greynoc_detector_engine.models.threat import ThreatRecord
from greynoc_detector_engine.scoring.ai_attack_score import AIAttackScorer
from greynoc_detector_engine.scoring.exploitability import ExploitabilityScorer


class RiskScorer:
    """Fuse reactive scores with the predictive forecast into a final risk score.

    When a predictive forecast is available it dominates (weight 0.45) — that
    is the point of a predictive engine. The reactive scores (exploitability,
    AI-abuse, severity, confidence) still anchor the bottom of the score so
    that "no prediction available" never collapses to 0.
    """

    def __init__(self) -> None:
        self.exploitability = ExploitabilityScorer()
        self.ai_attack = AIAttackScorer()

    def score(
        self,
        *,
        threat: ThreatRecord,
        cve: CVERecord | None = None,
        kev: KEVRecord | None = None,
    ) -> ScoreResult:
        exploitability = self.exploitability.score(cve=cve, kev=kev, threat=threat)
        ai_abuse = self.ai_attack.score(threat)
        confidence_component = threat.confidence * 10
        severity_component = {
            "low": 5,
            "medium": 15,
            "high": 25,
            "critical": 35,
        }[threat.severity.value]

        predictive_score = (
            threat.predictive_score.numeric_score if threat.predictive_score else None
        )

        reasons: list[str] = [
            f"Exploitability contributes {exploitability.numeric_score:.1f} before weighting.",
            f"AI-abuse contributes {ai_abuse.numeric_score:.1f} before weighting.",
            f"Threat severity {threat.severity.value} contributes {severity_component} points.",
            f"Confidence {threat.confidence:.2f} contributes {confidence_component:.1f} points.",
        ]

        if predictive_score is not None:
            final = (
                predictive_score * 0.45
                + exploitability.numeric_score * 0.25
                + ai_abuse.numeric_score * 0.10
                + severity_component
                + confidence_component
            )
            reasons.append(
                f"Predictive forecast contributes {predictive_score * 0.45:.1f} (weight 0.45)."
            )
            if threat.attack_forecast is not None:
                reasons.append(
                    f"Forecast horizon {threat.attack_forecast.horizon.value} "
                    f"(p50 {threat.attack_forecast.horizon_days_p50}d)."
                )
        else:
            final = (
                exploitability.numeric_score * 0.45
                + ai_abuse.numeric_score * 0.20
                + severity_component
                + confidence_component
            )
            reasons.append("No predictive forecast available; fell back to reactive weighting.")

        final_score = min(100.0, round(final, 2))
        signals: dict[str, object] = {
            "exploitability": exploitability.model_dump(mode="json"),
            "ai_abuse": ai_abuse.model_dump(mode="json"),
            "severity": threat.severity.value,
            "confidence": threat.confidence,
            "predictive_score": predictive_score,
        }
        if threat.attack_forecast is not None:
            signals["attack_forecast"] = threat.attack_forecast.model_dump(mode="json")

        return ScoreResult(
            score=final_score,
            label=score_label(final_score),
            reasons=reasons,
            contributing_signals=signals,
        )
