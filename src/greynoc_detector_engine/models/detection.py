from __future__ import annotations

from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from greynoc_detector_engine.models.source import SourceReference


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
    assumptions: list[str] = Field(default_factory=list)
    references: list[SourceReference] = Field(default_factory=list)
    confidence: float = Field(default=0.4, ge=0, le=1)

    @property
    def required_logs(self) -> list[str]:
        return self.required_telemetry

    @property
    def query(self) -> str:
        return self.rule_query
