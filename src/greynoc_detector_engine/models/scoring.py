from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from greynoc_detector_engine.utils.time import utc_now


class ScoreLabel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScoreResult(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    score: float = Field(ge=0, le=100, validation_alias="numeric_score")
    label: ScoreLabel
    reasons: list[str] = Field(default_factory=list)
    contributing_signals: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=utc_now)

    @property
    def numeric_score(self) -> float:
        return self.score


def score_label(score: float) -> ScoreLabel:
    if score >= 85:
        return ScoreLabel.CRITICAL
    if score >= 70:
        return ScoreLabel.HIGH
    if score >= 40:
        return ScoreLabel.MEDIUM
    return ScoreLabel.LOW
