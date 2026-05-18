from __future__ import annotations

from datetime import date

from pydantic import BaseModel, ConfigDict, Field

from greynoc_detection_engine.models.source import SourceReference


class KEVRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cve_id: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$")
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: date | None = None
    short_description: str
    required_action: str
    due_date: date | None = None
    known_ransomware_campaign_use: str | None = None
    notes: str | None = None
    source_references: list[SourceReference] = Field(default_factory=list)
