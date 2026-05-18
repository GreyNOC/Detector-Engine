from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from greynoc_detection_engine.models.risk import ScoreResult, score_label


class SignalInputs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    independent_sources: int = Field(default=0, ge=0)
    trusted_sources: int = Field(default=0, ge=0)
    news_mentions: int = Field(default=0, ge=0)
    github_mentions: int = Field(default=0, ge=0)
    recent_days: int = Field(default=30, ge=0)


class SignalScorer:
    def score(self, inputs: SignalInputs) -> ScoreResult:
        score = 0.0
        reasons: list[str] = []
        score += min(25, inputs.independent_sources * 5)
        score += min(20, inputs.trusted_sources * 8)
        score += min(20, inputs.news_mentions * 3)
        score += min(20, inputs.github_mentions * 4)

        if inputs.recent_days <= 3:
            score += 15
            reasons.append("Signals are very recent.")
        elif inputs.recent_days <= 14:
            score += 8
            reasons.append("Signals are recent enough to merit monitoring.")

        if inputs.independent_sources:
            reasons.append(f"{inputs.independent_sources} independent sources mention the signal.")
        if inputs.trusted_sources:
            reasons.append(f"{inputs.trusted_sources} trusted sources mention the signal.")
        if inputs.github_mentions:
            reasons.append(
                f"{inputs.github_mentions} GitHub metadata references mention the signal."
            )

        final_score = min(100, score)
        return ScoreResult(
            numeric_score=final_score,
            label=score_label(final_score),
            reasons=reasons or ["No cross-source signal strength was available."],
            contributing_signals=inputs.model_dump(),
        )
