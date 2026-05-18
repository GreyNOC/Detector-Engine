from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from greynoc_detector_engine.models.source import SourceReference


class CVERecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cve_id: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$")
    description: str
    published_date: datetime | None = None
    last_modified_date: datetime | None = None
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    cvss_vector: str | None = None
    cwe: list[str] = Field(default_factory=list)
    affected_products: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    exploit_references: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    source_references: list[SourceReference] = Field(default_factory=list)
