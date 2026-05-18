from __future__ import annotations

from greynoc_detection_engine.models.source import SourceReference
from greynoc_detection_engine.models.threat import ThreatRecord
from greynoc_detection_engine.utils.hashing import stable_hash
from greynoc_detection_engine.utils.text import normalize_whitespace


def threat_deduplication_key(threat: ThreatRecord) -> str:
    if threat.related_cves:
        return "cve:" + ",".join(sorted(threat.related_cves))
    normalized_title = normalize_whitespace(threat.title).lower()
    return f"title:{stable_hash(normalized_title)}"


def merge_threats(existing: ThreatRecord, incoming: ThreatRecord) -> ThreatRecord:
    merged = existing.model_copy(deep=True)
    merged.affected_products = sorted(
        set(existing.affected_products) | set(incoming.affected_products)
    )
    merged.related_cves = sorted(set(existing.related_cves) | set(incoming.related_cves))
    merged.related_kev_entries = sorted(
        set(existing.related_kev_entries) | set(incoming.related_kev_entries)
    )
    merged.tactics_techniques_procedures = sorted(
        set(existing.tactics_techniques_procedures) | set(incoming.tactics_techniques_procedures)
    )
    merged.mitre_attack_mapping = sorted(
        set(existing.mitre_attack_mapping) | set(incoming.mitre_attack_mapping)
    )
    merged.source_references = _merge_references(
        existing.source_references,
        incoming.source_references,
    )
    merged.observed_indicators = list(existing.observed_indicators)
    for indicator in incoming.observed_indicators:
        if indicator not in merged.observed_indicators:
            merged.observed_indicators.append(indicator)
    if incoming.last_seen and (merged.last_seen is None or incoming.last_seen > merged.last_seen):
        merged.last_seen = incoming.last_seen
    if incoming.first_seen and (
        merged.first_seen is None or incoming.first_seen < merged.first_seen
    ):
        merged.first_seen = incoming.first_seen
    merged.confidence = max(existing.confidence, incoming.confidence)
    if incoming.ai_attack_type and not merged.ai_attack_type:
        merged.ai_attack_type = incoming.ai_attack_type
    merged.version += 1
    merged.changelog.append(f"Merged duplicate signal from {incoming.threat_id}.")
    return merged


def _merge_references(
    existing: list[SourceReference],
    incoming: list[SourceReference],
) -> list[SourceReference]:
    by_hash = {reference.content_hash: reference for reference in existing}
    for reference in incoming:
        by_hash.setdefault(reference.content_hash, reference)
    return list(by_hash.values())
