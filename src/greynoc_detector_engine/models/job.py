"""Lightweight job-history model for the detection engine.

Job history exists to give SOC operators a single audit trail of every
ingest / correlate / predict / score / detection-generation run, with
its outcome and a compact summary. It is intentionally simple: no
queues, no distributed locks, no external services. The engine writes
one row per orchestrated run.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from greynoc_detector_engine.utils.time import utc_now


class JobStatus(StrEnum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class JobHistoryEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    job_id: str = Field(default_factory=lambda: f"job-{uuid4().hex[:12]}")
    job_type: str = Field(min_length=1, max_length=120)
    status: JobStatus
    started_at: datetime = Field(default_factory=utc_now)
    finished_at: datetime | None = None
    error: str | None = Field(default=None, max_length=4000)
    result_summary: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _validate_timestamps(self) -> JobHistoryEntry:
        if self.finished_at is not None and self.finished_at < self.started_at:
            raise ValueError("finished_at must be greater than or equal to started_at")
        if self.status == JobStatus.RUNNING and self.finished_at is not None:
            raise ValueError("running jobs cannot carry a finished_at value")
        if self.status == JobStatus.FAILED and not self.error:
            raise ValueError("failed jobs must include an error message")
        return self
