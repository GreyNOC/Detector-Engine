from __future__ import annotations

from greynoc_detector_engine.models.cve import CVERecord
from greynoc_detector_engine.models.threat import AIAttackType, ThreatRecord
from greynoc_detector_engine.scoring.early_warning import (
    EarlyWarningScorer,
    EarlyWarningSignals,
)
from greynoc_detector_engine.scoring.exploitability import ExploitabilityScorer


def test_exploitability_score_is_explainable() -> None:
    cve = CVERecord(
        cve_id="CVE-2026-12345",
        description="Example",
        cvss_score=9.8,
        exploit_references=["https://github.com/example/poc"],
    )
    score = ExploitabilityScorer().score(cve=cve)
    assert score.numeric_score > 40
    assert score.model_dump()["score"] == score.numeric_score
    assert score.reasons
    assert score.contributing_signals["exploit_reference_count"] == 1


def test_early_warning_score_uses_weighted_signals() -> None:
    score = EarlyWarningScorer().score(
        EarlyWarningSignals(
            kev_presence=True,
            cvss_score=9.8,
            exploit_reference_count=2,
            trusted_source_mentions=2,
            ransomware_association=True,
            independent_sources=3,
            recency_days=1,
        )
    )
    assert score.label in {"medium", "high", "critical"}
    assert any("KEV" in reason for reason in score.reasons)


def test_ai_attack_threat_can_be_scored() -> None:
    threat = ThreatRecord(
        title="RAG poisoning against support bot",
        summary="Attackers used RAG poisoning against a model context workflow.",
        category="ai_enabled_threat",
        ai_attack_type=AIAttackType.RAG_POISONING,
    )
    score = EarlyWarningScorer().score(
        EarlyWarningSignals(ai_enabled_relevance=1.0, independent_sources=2)
    )
    assert threat.ai_attack_type == AIAttackType.RAG_POISONING
    assert score.numeric_score > 0
