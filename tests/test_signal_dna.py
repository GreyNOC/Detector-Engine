from __future__ import annotations

from greynoc_detector_engine.intelligence.signal_dna import SignalStrength, build_signal_dna
from greynoc_detector_engine.models.source import SourceReference
from greynoc_detector_engine.models.threat import AIAttackType, ThreatRecord


def test_signal_dna_builds_stable_fingerprint_and_strength() -> None:
    threat = ThreatRecord(
        title="AI Supply Chain CVE Activity",
        summary="Threat involving AI supply chain exposure.",
        category="ai_supply_chain",
        ai_attack_type=AIAttackType.AI_SUPPLY_CHAIN_COMPROMISE,
        affected_products=["example:package"],
        related_cves=["CVE-2026-12345"],
        related_kev_entries=["CVE-2026-12345"],
        detection_opportunities=["Monitor package install telemetry."],
        recommended_soc_actions=["Hunt for package install telemetry."],
        source_references=[
            SourceReference(
                source="test-source",
                title="Example advisory",
                url="https://example.test/advisory",
                content_hash="abc123",
                raw_excerpt="AI supply chain context.",
            ),
            SourceReference(
                source="second-source",
                title="Second advisory",
                url="https://example.test/second-advisory",
                content_hash="def456",
                raw_excerpt="Additional CVE and AI supply chain context.",
            ),
        ],
    )

    dna = build_signal_dna(threat)
    repeated = build_signal_dna(threat)

    assert dna.fingerprint == repeated.fingerprint
    assert dna.fingerprint.startswith("gndna-")
    assert dna.ai_relevance is True
    assert dna.strength in {
        SignalStrength.MODERATE,
        SignalStrength.STRONG,
        SignalStrength.EXCEPTIONAL,
    }
    assert "cve-2026-12345" in dna.signature_terms
