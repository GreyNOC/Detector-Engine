from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from greynoc_detector_engine.utils.time import utc_now


class AssetExposure(StrEnum):
    INTERNAL = "internal"
    DMZ = "dmz"
    INTERNET_FACING = "internet_facing"
    CLOUD_PUBLIC = "cloud_public"


class AssetCriticality(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CROWN_JEWEL = "crown_jewel"


class AssetRecord(BaseModel):
    """A defender's own asset declared in their inventory."""

    model_config = ConfigDict(extra="forbid")

    asset_id: str
    name: str
    vendor: str | None = None
    product: str | None = None
    version: str | None = None
    exposure: AssetExposure = AssetExposure.INTERNAL
    criticality: AssetCriticality = AssetCriticality.MEDIUM
    sector: str | None = None
    business_owner: str | None = None
    tags: list[str] = Field(default_factory=list)
    last_seen: datetime = Field(default_factory=utc_now)


class TargetLikelihood(BaseModel):
    """How likely a known asset is to be targeted by a given threat."""

    model_config = ConfigDict(extra="forbid")

    asset_id: str
    threat_id: str
    likelihood: float = Field(ge=0.0, le=1.0)
    blast_radius: float = Field(ge=0.0, le=1.0)
    reasons: list[str] = Field(default_factory=list)
