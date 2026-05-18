from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from greynoc_detector_engine.utils.time import utc_now


class TimestampedModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
