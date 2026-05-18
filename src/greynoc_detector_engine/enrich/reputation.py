from __future__ import annotations

import re
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from greynoc_detector_engine.models.indicator import Indicator, IndicatorType


class ReputationVerdict(StrEnum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


class IndicatorReputation(BaseModel):
    """Aggregated, source-attributed reputation for a single IOC."""

    model_config = ConfigDict(extra="forbid")

    value: str
    type: IndicatorType
    verdict: ReputationVerdict
    confidence: float = Field(ge=0.0, le=1.0)
    sources: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)


# Well-known sinkhole / research / benign-by-context patterns used to suppress
# noisy correlations. These are *very* small and conservative.
BENIGN_DOMAIN_HINTS = (
    "google.com",
    "microsoft.com",
    "cisa.gov",
    "nvd.nist.gov",
    "github.com",
)

PRIVATE_IPV4 = re.compile(r"^(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[0-1])\.|127\.|169\.254\.)")


class IndicatorReputationEngine:
    """Light-weight, deterministic reputation aggregation.

    Designed to work with the OSINT ingestors (ThreatFox, URLhaus) and any
    explicitly-loaded blocklists. No third-party API calls — we rely on signals
    that have already been ingested through documented public feeds.
    """

    def __init__(self) -> None:
        self._malicious: dict[str, IndicatorReputation] = {}

    def upsert(self, reputation: IndicatorReputation) -> None:
        key = self._key(reputation.value, reputation.type)
        existing = self._malicious.get(key)
        if existing is None:
            self._malicious[key] = reputation
            return
        merged_sources = sorted(set(existing.sources) | set(reputation.sources))
        merged_tags = sorted(set(existing.tags) | set(reputation.tags))
        merged_reasons = list(dict.fromkeys(existing.reasons + reputation.reasons))
        verdict = self._strongest_verdict(existing.verdict, reputation.verdict)
        confidence = min(1.0, max(existing.confidence, reputation.confidence) + 0.05)
        self._malicious[key] = IndicatorReputation(
            value=reputation.value,
            type=reputation.type,
            verdict=verdict,
            confidence=confidence,
            sources=merged_sources,
            tags=merged_tags,
            reasons=merged_reasons,
        )

    def lookup(self, indicator: Indicator) -> IndicatorReputation:
        if existing := self._malicious.get(self._key(indicator.value, indicator.type)):
            return existing
        return self._derive(indicator)

    @staticmethod
    def _key(value: str, indicator_type: IndicatorType) -> str:
        return f"{indicator_type.value}:{value.lower()}"

    @staticmethod
    def _derive(indicator: Indicator) -> IndicatorReputation:
        verdict = ReputationVerdict.UNKNOWN
        confidence = 0.2
        tags: list[str] = []
        reasons: list[str] = []
        value = indicator.value.lower()

        if indicator.type == IndicatorType.IPV4 and PRIVATE_IPV4.match(value):
            verdict = ReputationVerdict.BENIGN
            confidence = 0.9
            tags.append("rfc1918")
            reasons.append("Address is RFC1918 / loopback; not a routable IOC.")

        if indicator.type == IndicatorType.DOMAIN and any(
            value.endswith(h) for h in BENIGN_DOMAIN_HINTS
        ):
            verdict = ReputationVerdict.BENIGN
            confidence = max(confidence, 0.7)
            tags.append("well-known")
            reasons.append("Domain matches a public well-known infrastructure hint.")

        return IndicatorReputation(
            value=indicator.value,
            type=indicator.type,
            verdict=verdict,
            confidence=confidence,
            sources=[indicator.source] if indicator.source else [],
            tags=tags,
            reasons=reasons,
        )

    @staticmethod
    def _strongest_verdict(a: ReputationVerdict, b: ReputationVerdict) -> ReputationVerdict:
        order = {
            ReputationVerdict.MALICIOUS: 3,
            ReputationVerdict.SUSPICIOUS: 2,
            ReputationVerdict.UNKNOWN: 1,
            ReputationVerdict.BENIGN: 0,
        }
        return a if order[a] >= order[b] else b
