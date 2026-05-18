from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from greynoc_detector_engine.utils.time import utc_now


class AnalystVerdict(StrEnum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    BENIGN_INTENT = "benign_intent"
    DUPLICATE = "duplicate"
    NEEDS_CONTEXT = "needs_context"


class ThreatFeedback(BaseModel):
    """Analyst feedback on a threat, used to tune predictive weights."""

    model_config = ConfigDict(extra="forbid")

    feedback_id: str
    threat_id: str
    verdict: AnalystVerdict
    analyst: str = "anonymous"
    notes: str = ""
    submitted_at: datetime = Field(default_factory=utc_now)
