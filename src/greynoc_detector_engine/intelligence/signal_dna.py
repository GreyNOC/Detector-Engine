from __future__ import annotations

import hashlib
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from greynoc_detector_engine.models.threat import ThreatRecord


class SignalStrength(StrEnum):
    WEAK = "weak"
    MODERATE = "moderate"
    STRONG = "strong"
    EXCEPTIONAL = "exceptional"


class SignalDNA(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fingerprint: str
    strength: SignalStrength
    source_count: int
    cve_count: int
    kev_count: int
    detection_opportunity_count: int
    ai_relevance: bool
    evidence_density: float = Field(ge=0, le=1)
    recommended_action_density: float = Field(ge=0, le=1)
    signature_terms: list[str] = Field(default_factory=list)


def build_signal_dna(threat: ThreatRecord) -> SignalDNA:
    source_count = len(threat.source_references)
    cve_count = len(threat.related_cves)
    kev_count = len(threat.related_kev_entries)
    detection_count = len(threat.detection_opportunities)
    evidence_density = _bounded_ratio(source_count + cve_count + kev_count, 8)
    action_density = _bounded_ratio(len(threat.recommended_soc_actions), 6)
    ai_relevance = threat.ai_attack_type is not None
    signature_terms = _signature_terms(threat)
    fingerprint = _fingerprint(threat, signature_terms)
    strength = _strength(
        evidence_density=evidence_density,
        action_density=action_density,
        source_count=source_count,
        cve_count=cve_count,
        kev_count=kev_count,
        detection_count=detection_count,
        ai_relevance=ai_relevance,
    )
    return SignalDNA(
        fingerprint=fingerprint,
        strength=strength,
        source_count=source_count,
        cve_count=cve_count,
        kev_count=kev_count,
        detection_opportunity_count=detection_count,
        ai_relevance=ai_relevance,
        evidence_density=evidence_density,
        recommended_action_density=action_density,
        signature_terms=signature_terms,
    )


def _bounded_ratio(value: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round(min(1.0, value / denominator), 3)


def _strength(
    *,
    evidence_density: float,
    action_density: float,
    source_count: int,
    cve_count: int,
    kev_count: int,
    detection_count: int,
    ai_relevance: bool,
) -> SignalStrength:
    score = 0.0
    score += evidence_density * 40
    score += action_density * 15
    score += min(15, source_count * 3)
    score += min(10, cve_count * 3)
    score += min(10, kev_count * 5)
    score += min(5, detection_count)
    score += 5 if ai_relevance else 0
    if score >= 85:
        return SignalStrength.EXCEPTIONAL
    if score >= 65:
        return SignalStrength.STRONG
    if score >= 35:
        return SignalStrength.MODERATE
    return SignalStrength.WEAK


def _signature_terms(threat: ThreatRecord) -> list[str]:
    raw_terms: set[str] = set()
    raw_terms.add(threat.category)
    raw_terms.update(threat.affected_products)
    raw_terms.update(threat.related_cves)
    raw_terms.update(threat.related_kev_entries)
    raw_terms.update(threat.tactics_techniques_procedures)
    raw_terms.update(threat.mitre_attack_mapping)
    if threat.ai_attack_type:
        raw_terms.add(threat.ai_attack_type.value)
    for reference in threat.source_references:
        raw_terms.add(reference.source)
        raw_terms.add(reference.title)
    normalized = sorted(
        {term.strip().lower() for term in raw_terms if term and len(term.strip()) >= 3}
    )
    return normalized[:25]


def _fingerprint(threat: ThreatRecord, signature_terms: list[str]) -> str:
    material = "|".join(
        [
            threat.title.lower(),
            threat.category.lower(),
            *signature_terms,
        ]
    )
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return f"gndna-{digest[:16]}"
