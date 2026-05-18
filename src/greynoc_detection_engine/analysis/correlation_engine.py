from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from greynoc_detection_engine.analysis.narrative_builder import NarrativeBuilder
from greynoc_detection_engine.analysis.soc_recommendations import SOCRecommendationBuilder
from greynoc_detection_engine.models.cve import CVERecord
from greynoc_detection_engine.models.kev import KEVRecord
from greynoc_detection_engine.models.source import SourceItem
from greynoc_detection_engine.models.threat import ThreatRecord, ThreatSeverity
from greynoc_detection_engine.normalize.entity_extractor import EntityExtractor
from greynoc_detection_engine.normalize.normalizer import ThreatNormalizer
from greynoc_detection_engine.scoring.ai_attack_score import AIAttackScorer
from greynoc_detection_engine.scoring.early_warning_score import (
    EarlyWarningScorer,
    EarlyWarningSignals,
)
from greynoc_detection_engine.scoring.exploitability_score import ExploitabilityScorer
from greynoc_detection_engine.scoring.risk_score import RiskScorer


class CorrelationRelationship(BaseModel):
    model_config = ConfigDict(extra="forbid")

    relationship_type: str
    left: str
    right: str
    confidence: float = Field(ge=0, le=1)
    reason: str


class CorrelationReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    relationships: list[CorrelationRelationship] = Field(default_factory=list)
    threats: list[ThreatRecord] = Field(default_factory=list)


class CorrelationEngine:
    def __init__(self) -> None:
        self.extractor = EntityExtractor()
        self.normalizer = ThreatNormalizer()
        self.exploitability = ExploitabilityScorer()
        self.ai_attack = AIAttackScorer()
        self.early_warning = EarlyWarningScorer()
        self.risk = RiskScorer()
        self.narratives = NarrativeBuilder()
        self.soc = SOCRecommendationBuilder()

    def correlate(
        self,
        *,
        cves: list[CVERecord],
        kev_entries: list[KEVRecord],
        source_items: list[SourceItem],
    ) -> CorrelationReport:
        relationships: list[CorrelationRelationship] = []
        threats: list[ThreatRecord] = []
        kev_by_cve = {entry.cve_id: entry for entry in kev_entries}
        items_by_cve = self._items_by_cve(source_items)

        for cve in cves:
            kev = kev_by_cve.get(cve.cve_id)
            threat = self.normalizer.from_cve(cve, kev=kev)
            related_items = items_by_cve.get(cve.cve_id, [])
            for item in related_items:
                threat.source_references.append(item.to_reference())
                relationships.append(
                    CorrelationRelationship(
                        relationship_type="cve_source_mention",
                        left=cve.cve_id,
                        right=item.item_id,
                        confidence=0.75,
                        reason="Source item mentions the CVE identifier.",
                    )
                )
            if kev:
                relationships.append(
                    CorrelationRelationship(
                        relationship_type="cve_kev",
                        left=cve.cve_id,
                        right=kev.cve_id,
                        confidence=0.95,
                        reason="CVE appears in the CISA Known Exploited Vulnerabilities catalog.",
                    )
                )
            threat = self._score_threat(threat, cve=cve, kev=kev, related_items=related_items)
            threats.append(threat)

        known_cves = {cve.cve_id for cve in cves}
        for item in source_items:
            entities = self.extractor.extract(f"{item.title} {item.raw_content}")
            if entities.cve_ids and any(cve_id in known_cves for cve_id in entities.cve_ids):
                continue
            if not entities.ai_terms and not entities.exploit_terms:
                continue
            threat = self.normalizer.from_source_item(item)
            threat = self._score_threat(threat, cve=None, kev=None, related_items=[item])
            threats.append(threat)

        return CorrelationReport(relationships=relationships, threats=threats)

    def _score_threat(
        self,
        threat: ThreatRecord,
        *,
        cve: CVERecord | None,
        kev: KEVRecord | None,
        related_items: list[SourceItem],
    ) -> ThreatRecord:
        scored = threat.model_copy(deep=True)
        text = " ".join([item.title + " " + item.raw_content for item in related_items])
        entities = self.extractor.extract(text)
        github_mentions = sum(1 for item in related_items if "github" in item.source_id.lower())
        news_mentions = len(related_items) - github_mentions
        independent_sources = len({item.source_id for item in related_items})
        ai_relevance = 1.0 if scored.ai_attack_type or entities.ai_terms else 0.0
        ew_signals = EarlyWarningSignals(
            kev_presence=kev is not None,
            cvss_score=cve.cvss_score if cve else None,
            exploit_reference_count=len(cve.exploit_references) if cve else 0,
            github_velocity=min(1.0, github_mentions / 3),
            news_velocity=min(1.0, news_mentions / 5),
            trusted_source_mentions=sum(
                1 for ref in scored.source_references if ref.confidence >= 0.8
            ),
            ransomware_association="ransomware" in text.lower()
            or (kev.known_ransomware_campaign_use == "Known" if kev else False),
            affected_product_popularity=0.5 if scored.affected_products else 0.0,
            ai_enabled_relevance=ai_relevance,
            vendor_emergency_language="emergency patch" in text.lower(),
            independent_sources=independent_sources,
            recency_days=0 if related_items else 30,
        )
        scored.exploitability_score = self.exploitability.score(cve=cve, kev=kev, threat=scored)
        scored.early_warning_score = self.early_warning.score(ew_signals)
        scored.ai_abuse_score = self.ai_attack.score(scored)
        risk = self.risk.score(threat=scored, cve=cve, kev=kev)
        scored.severity = ThreatSeverity(risk.label.value)
        scored.summary = self.narratives.build(scored)
        scored.recommended_soc_actions = self.soc.recommend(scored, cve=cve, kev=kev)
        scored.changelog.append("Correlation engine applied explainable scoring.")
        return scored

    def _items_by_cve(self, items: list[SourceItem]) -> dict[str, list[SourceItem]]:
        grouped: dict[str, list[SourceItem]] = {}
        for item in items:
            cve_ids = self.extractor.extract(f"{item.title} {item.raw_content}").cve_ids
            for cve_id in cve_ids:
                grouped.setdefault(cve_id, []).append(item)
        return grouped
