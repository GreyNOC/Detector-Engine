from __future__ import annotations

from greynoc_detection_engine.catalog.deduplication import merge_threats, threat_deduplication_key
from greynoc_detection_engine.models.threat import ThreatRecord


def test_deduplication_prefers_related_cves() -> None:
    threat = ThreatRecord(
        title="Example",
        summary="A",
        category="vulnerability",
        related_cves=["CVE-2026-12345"],
    )
    assert threat_deduplication_key(threat) == "cve:CVE-2026-12345"


def test_merge_threats_preserves_provenance_and_versions() -> None:
    first = ThreatRecord(title="A", summary="A", category="signal", affected_products=["A"])
    second = ThreatRecord(title="A", summary="B", category="signal", affected_products=["B"])
    merged = merge_threats(first, second)
    assert merged.version == 2
    assert merged.affected_products == ["A", "B"]
    assert merged.changelog
