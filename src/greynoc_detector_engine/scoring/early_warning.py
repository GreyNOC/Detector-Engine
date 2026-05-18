from __future__ import annotations

from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field

from greynoc_detector_engine.models.scoring import ScoreResult, score_label


class EarlyWarningSignals(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kev_presence: bool = False
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    exploit_reference_count: int = Field(default=0, ge=0)
    github_velocity: float = Field(default=0, ge=0)
    news_velocity: float = Field(default=0, ge=0)
    trusted_source_mentions: int = Field(default=0, ge=0)
    ransomware_association: bool = False
    affected_product_popularity: float = Field(default=0, ge=0, le=1)
    ai_enabled_relevance: float = Field(default=0, ge=0, le=1)
    vendor_emergency_language: bool = False
    independent_sources: int = Field(default=0, ge=0)
    recency_days: int = Field(default=30, ge=0)


class EarlyWarningScorer:
    weights: ClassVar[dict[str, int]] = {
        "kev_presence": 16,
        "cvss_severity": 12,
        "exploit_references": 12,
        "github_velocity": 10,
        "news_velocity": 10,
        "trusted_source_mentions": 10,
        "ransomware_association": 8,
        "affected_product_popularity": 6,
        "ai_enabled_relevance": 6,
        "vendor_emergency_language": 5,
        "independent_sources": 3,
        "recency": 2,
    }

    def score(self, signals: EarlyWarningSignals) -> ScoreResult:
        score = 0.0
        reasons: list[str] = []
        contributions: dict[str, float | int | bool | None] = signals.model_dump()

        if signals.kev_presence:
            score += self.weights["kev_presence"]
            reasons.append("CISA KEV presence indicates confirmed exploitation.")

        if signals.cvss_score is not None:
            component = self.weights["cvss_severity"] * (signals.cvss_score / 10)
            score += component
            reasons.append(f"CVSS {signals.cvss_score} contributes {component:.1f} points.")

        if signals.exploit_reference_count:
            component = min(
                self.weights["exploit_references"],
                3 * signals.exploit_reference_count,
            )
            score += component
            reasons.append(f"{signals.exploit_reference_count} exploit references were observed.")

        score += self._bounded_component("github_velocity", signals.github_velocity, reasons)
        score += self._bounded_component("news_velocity", signals.news_velocity, reasons)

        if signals.trusted_source_mentions:
            component = min(
                self.weights["trusted_source_mentions"],
                2 * signals.trusted_source_mentions,
            )
            score += component
            reasons.append(
                f"{signals.trusted_source_mentions} trusted-source mentions were observed."
            )

        if signals.ransomware_association:
            score += self.weights["ransomware_association"]
            reasons.append("Ransomware association increases operational urgency.")

        if signals.affected_product_popularity:
            component = (
                self.weights["affected_product_popularity"] * signals.affected_product_popularity
            )
            score += component
            reasons.append("Affected product popularity increases likely exposure.")

        if signals.ai_enabled_relevance:
            component = self.weights["ai_enabled_relevance"] * signals.ai_enabled_relevance
            score += component
            reasons.append("AI-enabled relevance increases emerging-tech monitoring priority.")

        if signals.vendor_emergency_language:
            score += self.weights["vendor_emergency_language"]
            reasons.append("Vendor emergency language was detected.")

        if signals.independent_sources:
            component = min(self.weights["independent_sources"], signals.independent_sources)
            score += component
            reasons.append(f"{signals.independent_sources} independent sources support the signal.")

        if signals.recency_days <= 3:
            score += self.weights["recency"]
            reasons.append("Signal was observed within the last three days.")

        final_score = min(100, round(score, 2))
        return ScoreResult(
            score=final_score,
            label=score_label(final_score),
            reasons=reasons or ["No early-warning factors were present."],
            contributing_signals=contributions,
        )

    def _bounded_component(self, name: str, value: float, reasons: list[str]) -> float:
        weight = self.weights[name]
        component = min(weight, value * weight)
        if component:
            reasons.append(f"{name.replace('_', ' ')} contributes {component:.1f} points.")
        return component
