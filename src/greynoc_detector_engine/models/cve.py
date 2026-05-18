from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from greynoc_detector_engine.models.source import SourceReference


class ExploitMaturity(StrEnum):
    UNPROVEN = "unproven"
    PROOF_OF_CONCEPT = "proof_of_concept"
    FUNCTIONAL = "functional"
    HIGH = "high"
    NOT_DEFINED = "not_defined"


class CVERecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cve_id: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$")
    description: str
    published_date: datetime | None = None
    last_modified_date: datetime | None = None
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    cvss_vector: str | None = None
    epss_score: float | None = Field(default=None, ge=0, le=1)
    exploit_maturity: ExploitMaturity = ExploitMaturity.NOT_DEFINED
    patch_available: bool | None = None
    internet_exposed: bool | None = None
    asset_exposure_score: float | None = Field(default=None, ge=0, le=1)
    cwe: list[str] = Field(default_factory=list)
    affected_products: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    exploit_references: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    source_references: list[SourceReference] = Field(default_factory=list)
