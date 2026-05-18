from __future__ import annotations

from greynoc_detection_engine.models.risk import ScoreResult, score_label
from greynoc_detection_engine.models.threat import ThreatRecord
from greynoc_detection_engine.normalize.ai_attack_classifier import AIAttackClassifier


class AIAttackScorer:
    def __init__(self) -> None:
        self.classifier = AIAttackClassifier()

    def score(self, threat: ThreatRecord) -> ScoreResult:
        text = " ".join([threat.title, threat.summary, *threat.detection_opportunities])
        classification = self.classifier.classify(text)
        score = 0.0
        reasons: list[str] = []
        signals: dict[str, object] = {}

        if threat.ai_attack_type:
            score += 60
            signals["ai_attack_type"] = threat.ai_attack_type.value
            reasons.append(f"Threat is classified as {threat.ai_attack_type.value}.")

        if classification.attack_type:
            score += 25 * classification.confidence
            signals["matched_terms"] = classification.matched_terms
            reasons.extend(classification.rationale)

        indicator_count = sum(
            1 for indicator in threat.observed_indicators if indicator.type == "ai_attack_term"
        )
        if indicator_count:
            score += min(15, indicator_count * 5)
            signals["ai_indicator_count"] = indicator_count
            reasons.append(f"{indicator_count} AI-specific observed indicators are attached.")

        final_score = min(100, score)
        return ScoreResult(
            numeric_score=final_score,
            label=score_label(final_score),
            reasons=reasons or ["No AI-specific abuse signal was detected."],
            contributing_signals=signals,
        )
