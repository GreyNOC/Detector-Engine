from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from greynoc_detector_engine.models.source import SourceReference
from greynoc_detector_engine.utils.time import utc_now


class DetectionKind(StrEnum):
    SIGMA = "sigma"
    YARA = "yara"
    SURICATA = "suricata"
    SPLUNK = "splunk"
    ELASTIC = "elastic"
    DEFENDER = "defender"


class DetectionStatus(StrEnum):
    DRAFT = "draft"
    VALIDATED = "validated"
    DEPRECATED = "deprecated"


class ValidationResult(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    NEEDS_TUNING = "needs_tuning"
    INFORMATIONAL = "informational"


class ValidationEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    result: ValidationResult
    summary: str = Field(min_length=1, max_length=2000)
    telemetry_source: str | None = Field(default=None, max_length=200)
    sample_size: int | None = Field(default=None, ge=0)
    true_positive_count: int | None = Field(default=None, ge=0)
    false_positive_count: int | None = Field(default=None, ge=0)
    reviewer: str | None = Field(default=None, max_length=200)
    created_at: datetime = Field(default_factory=utc_now)


class GeneratedDetection(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    detection_id: str = Field(default_factory=lambda: f"det-{uuid4().hex[:12]}")
    related_threat_id: str
    kind: DetectionKind
    title: str
    description: str
    status: DetectionStatus = DetectionStatus.DRAFT
    required_telemetry: list[str] = Field(default_factory=list, validation_alias="required_logs")
    rule_query: str = Field(validation_alias="query")
    false_positives: list[str] = Field(default_factory=list)
    validation_steps: list[str] = Field(default_factory=list)
    validation_evidence: list[ValidationEvidence] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    references: list[SourceReference] = Field(default_factory=list)
    confidence: float = Field(default=0.4, ge=0, le=1)

    @property
    def required_logs(self) -> list[str]:
        return self.required_telemetry

    @property
    def query(self) -> str:
        return self.rule_query
