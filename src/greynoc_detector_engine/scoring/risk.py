from __future__ import annotations

from greynoc_detector_engine.models.cve import CVERecord
from greynoc_detector_engine.models.kev import KEVRecord
from greynoc_detector_engine.models.scoring import ScoreResult, score_label
from greynoc_detector_engine.models.threat import ThreatRecord
from greynoc_detector_engine.scoring.ai_attack_score import AIAttackScorer
from greynoc_detector_engine.scoring.exploitability import ExploitabilityScorer


class RiskScorer:
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
        final_score = min(
            100,
            (exploitability.numeric_score * 0.45)
            + (ai_abuse.numeric_score * 0.2)
            + severity_component
            + confidence_component,
        )
        return ScoreResult(
            score=round(final_score, 2),
            label=score_label(final_score),
            reasons=[
                f"Exploitability contributes {exploitability.numeric_score:.1f} before weighting.",
                f"AI-abuse contributes {ai_abuse.numeric_score:.1f} before weighting.",
                f"Threat severity {threat.severity.value} contributes {severity_component} points.",
                f"Confidence {threat.confidence:.2f} contributes "
                f"{confidence_component:.1f} points.",
            ],
            contributing_signals={
                "exploitability": exploitability.model_dump(mode="json"),
                "ai_abuse": ai_abuse.model_dump(mode="json"),
                "severity": threat.severity.value,
                "confidence": threat.confidence,
            },
        )
