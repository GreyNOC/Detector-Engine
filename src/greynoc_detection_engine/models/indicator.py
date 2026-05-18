from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class IndicatorType(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    EMAIL = "email"
    CVE = "cve"
    PRODUCT = "product"
    VENDOR = "vendor"
    MALWARE_FAMILY = "malware_family"
    THREAT_ACTOR = "threat_actor"
    TOOL = "tool"
    TECHNIQUE = "technique"
    AI_ATTACK_TERM = "ai_attack_term"


class Indicator(BaseModel):
    model_config = ConfigDict(extra="forbid")

    value: str
    type: IndicatorType
    confidence: float = Field(default=0.5, ge=0, le=1)
    source: str | None = None
    context: str | None = None
