from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from greynoc_detector_engine.utils.time import utc_now


class SourceCategory(StrEnum):
    GOVERNMENT_ADVISORY = "government_advisory"
    VENDOR_ADVISORY = "vendor_advisory"
    SECURITY_RESEARCH_BLOG = "security_research_blog"
    INCIDENT_RESPONSE_FIRM = "incident_response_firm"
    MALWARE_ANALYSIS_BLOG = "malware_analysis_blog"
    AI_SECURITY_RESEARCH = "ai_security_research"
    GITHUB_REPOSITORY = "github_repository"
    RSS_FEED = "rss_feed"
    NEWS = "news"
    CVE = "cve"
    KEV = "kev"


class SourceType(StrEnum):
    CVE_JSON = "cve_json"
    KEV_JSON = "kev_json"
    RSS = "rss"
    BLOG = "blog"
    NEWS = "news"
    GITHUB_REPOSITORY = "github_repository"
    GITHUB_SEARCH = "github_search"


class SourceReliability(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERIFIED = "verified"


class SourceConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_id: str = Field(alias="id")
    name: str
    category: SourceCategory
    type: SourceType
    url: str | None = None
    enabled: bool = True
    reliability: SourceReliability = SourceReliability.MEDIUM
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SourceReference(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str | None = None
    title: str
    source: str
    author: str | None = None
    published_at: datetime | None = None
    fetched_at: datetime = Field(default_factory=utc_now)
    content_hash: str
    confidence: float = Field(default=0.5, ge=0, le=1)
    raw_excerpt: str = Field(default="", max_length=4000)


class SourceItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    item_id: str
    source_id: str
    title: str
    url: str | None = None
    author: str | None = None
    published_at: datetime | None = None
    fetched_at: datetime = Field(default_factory=utc_now)
    raw_content: str = ""
    raw_excerpt: str = Field(default="", max_length=4000)
    content_hash: str
    confidence: float = Field(default=0.5, ge=0, le=1)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def to_reference(self, source_name: str | None = None) -> SourceReference:
        return SourceReference(
            url=self.url,
            title=self.title,
            source=source_name or self.source_id,
            author=self.author,
            published_at=self.published_at,
            fetched_at=self.fetched_at,
            content_hash=self.content_hash,
            confidence=self.confidence,
            raw_excerpt=self.raw_excerpt,
        )
