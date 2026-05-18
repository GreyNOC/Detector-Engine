from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from greynoc_detector_engine.analysis.campaign import CampaignClusterer
from greynoc_detector_engine.analysis.narrative_builder import NarrativeBuilder
from greynoc_detector_engine.analysis.soc_recommendations import SOCRecommendationBuilder
from greynoc_detector_engine.config.settings import (
    load_attack_horizon_config,
    load_scoring_config,
)
from greynoc_detector_engine.enrich.epss import EPSSEnricher
from greynoc_detector_engine.enrich.reputation import IndicatorReputationEngine
from greynoc_detector_engine.enrich.threat_actor import ThreatActorAttributor
from greynoc_detector_engine.models.cve import CVERecord
from greynoc_detector_engine.models.kev import KEVRecord
from greynoc_detector_engine.models.prediction import CampaignCluster, EPSSScore
from greynoc_detector_engine.models.source import SourceItem
from greynoc_detector_engine.models.threat import ThreatRecord, ThreatSeverity
from greynoc_detector_engine.normalize.entity_extractor import EntityExtractor
from greynoc_detector_engine.normalize.normalizer import ThreatNormalizer
from greynoc_detector_engine.prediction.attack_forecast import AttackForecaster
from greynoc_detector_engine.prediction.features import (
    PredictiveContext,
    PredictiveFeatureBuilder,
)
from greynoc_detector_engine.prediction.signal_index import PredictionSignalIndex
from greynoc_detector_engine.scoring.ai_attack_score import AIAttackScorer
from greynoc_detector_engine.scoring.early_warning import (
    EarlyWarningScorer,
    EarlyWarningSignals,
)
from greynoc_detector_engine.scoring.exploitability import ExploitabilityScorer
from greynoc_detector_engine.scoring.predictive import PredictiveScorer
from greynoc_detector_engine.scoring.risk import RiskScorer


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
    campaigns: list[CampaignCluster] = Field(default_factory=list)


class CorrelationEngine:
    """The orchestrator: ingests normalized inputs and produces scored threats.

    Reactive pipeline:
        CVE/KEV/source items -> ThreatRecord -> exploitability / AI-abuse /
        early-warning scoring.

    Predictive pipeline (new):
        Threat + CVE + KEV + EPSS + source items + suspected actors + active
        campaign -> PredictiveContext -> AttackForecast -> ScoreResult fused
        into final risk.
    """

    def __init__(
        self,
        *,
        reputation: IndicatorReputationEngine | None = None,
        epss_enricher: EPSSEnricher | None = None,
    ) -> None:
        self.extractor = EntityExtractor()
        self.normalizer = ThreatNormalizer()
        self.exploitability = ExploitabilityScorer()
        self.ai_attack = AIAttackScorer()
        self.early_warning = EarlyWarningScorer()
        self.risk = RiskScorer()
        self.narratives = NarrativeBuilder()
        self.soc = SOCRecommendationBuilder()
        self.actor_attributor = ThreatActorAttributor()
        self.reputation = reputation or IndicatorReputationEngine()
        self.epss = epss_enricher or EPSSEnricher()
        self.feature_builder = PredictiveFeatureBuilder(
            reputation=self.reputation,
            actor_attributor=self.actor_attributor,
            epss=self.epss,
        )
        self.forecaster = AttackForecaster.from_config(
            scoring_config=load_scoring_config(),
            horizon_config=load_attack_horizon_config(),
            feature_builder=self.feature_builder,
        )
        self.predictive_scorer = PredictiveScorer()
        self.campaign = CampaignClusterer()

    def correlate(
        self,
        *,
        cves: list[CVERecord],
        kev_entries: list[KEVRecord],
        source_items: list[SourceItem],
        epss_scores: list[EPSSScore] | None = None,
        ransomware_posts_30d: int = 0,
        local_intrusion_pressure: float = 0.0,
    ) -> CorrelationReport:
        if epss_scores:
            self.epss.load(epss_scores)

        relationships: list[CorrelationRelationship] = []
        threats: list[ThreatRecord] = []
        kev_by_cve = {entry.cve_id: entry for entry in kev_entries}
        signal_index = PredictionSignalIndex.build(source_items)
        items_by_cve = signal_index.items_by_cve

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
            threat = self._score_threat(
                threat,
                cve=cve,
                kev=kev,
                related_items=related_items,
                source_items=source_items,
                ransomware_posts_30d=ransomware_posts_30d,
                local_intrusion_pressure=local_intrusion_pressure,
                signal_index=signal_index,
            )
            threats.append(threat)

        known_cves = {cve.cve_id for cve in cves}
        for item in source_items:
            entities = self.extractor.extract(f"{item.title} {item.raw_content}")
            if entities.cve_ids and any(cve_id in known_cves for cve_id in entities.cve_ids):
                continue
            if not entities.ai_terms and not entities.exploit_terms:
                continue
            threat = self.normalizer.from_source_item(item)
            threat = self._score_threat(
                threat,
                cve=None,
                kev=None,
                related_items=[item],
                source_items=source_items,
                ransomware_posts_30d=ransomware_posts_30d,
                local_intrusion_pressure=local_intrusion_pressure,
                signal_index=signal_index,
            )
            threats.append(threat)

        # Cluster into campaigns after each threat is scored so cluster cohesion
        # can in turn feed back into threats' active_campaign flag.
        campaigns = self.campaign.cluster(threats, source_items)
        cves_by_id = {cve.cve_id: cve for cve in cves}
        threats = self._mark_campaign_membership(
            threats,
            campaigns,
            cves_by_id=cves_by_id,
            kev_by_cve=kev_by_cve,
            source_items=source_items,
            ransomware_posts_30d=ransomware_posts_30d,
            local_intrusion_pressure=local_intrusion_pressure,
            signal_index=signal_index,
        )
        for cluster in campaigns:
            for tid in cluster.related_threat_ids:
                relationships.append(
                    CorrelationRelationship(
                        relationship_type="threat_campaign",
                        left=tid,
                        right=cluster.campaign_id,
                        confidence=cluster.cohesion,
                        reason=f"Threat assigned to campaign cluster {cluster.label}.",
                    )
                )

        return CorrelationReport(
            relationships=relationships,
            threats=threats,
            campaigns=campaigns,
        )

    def rescore(
        self,
        threat: ThreatRecord,
        *,
        cve: CVERecord | None = None,
        kev: KEVRecord | None = None,
        source_items: list[SourceItem] | None = None,
        ransomware_posts_30d: int = 0,
        local_intrusion_pressure: float = 0.0,
        signal_index: PredictionSignalIndex | None = None,
    ) -> ThreatRecord:
        """Re-run the full reactive + predictive scoring pipeline on a single threat."""
        source_items = source_items or []
        signal_index = signal_index or PredictionSignalIndex.build(source_items)
        return self._score_threat(
            threat,
            cve=cve,
            kev=kev,
            related_items=signal_index.source_items_for_cves(threat.related_cves),
            source_items=source_items,
            ransomware_posts_30d=ransomware_posts_30d,
            local_intrusion_pressure=local_intrusion_pressure,
            signal_index=signal_index,
        )

    def _score_threat(
        self,
        threat: ThreatRecord,
        *,
        cve: CVERecord | None,
        kev: KEVRecord | None,
        related_items: list[SourceItem],
        source_items: list[SourceItem],
        ransomware_posts_30d: int,
        local_intrusion_pressure: float = 0.0,
        campaign_active: bool = False,
        signal_index: PredictionSignalIndex | None = None,
    ) -> ThreatRecord:
        scored = threat.model_copy(deep=True)
        text = " ".join([item.title + " " + item.raw_content for item in related_items])
        entities = self.extractor.extract(text)
        github_mentions = sum(1 for item in related_items if "github" in item.source_id.lower())
        news_mentions = len(related_items) - github_mentions
        independent_sources = len({item.source_id for item in related_items})
        ai_relevance = 1.0 if scored.ai_attack_type or entities.ai_terms else 0.0

        # --- reactive scoring (unchanged behavior) ---
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

        # --- predictive scoring ---
        suspected_actors = self.actor_attributor.actor_ids(scored.title + " " + text)
        epss_score = None
        for cve_id in scored.related_cves:
            got = self.epss.for_cve(cve_id)
            if got is not None:
                epss_score = got
                break
        indexed_signal = (
            signal_index.signal_for_cves(scored.related_cves)
            if signal_index is not None and scored.related_cves
            else None
        )
        ctx = PredictiveContext(
            threat=scored,
            cve=cve,
            kev=kev,
            epss=epss_score,
            source_items=source_items,
            indexed_signal=indexed_signal,
            suspected_actors=suspected_actors,
            campaign_active=campaign_active,
            ransomware_claims_last_30d=ransomware_posts_30d,
            sectors_in_play=list(scored.sectors_at_risk),
            local_intrusion_pressure=local_intrusion_pressure,
        )
        forecast = self.forecaster.forecast(ctx)
        scored.attack_forecast = forecast
        scored.predictive_score = self.predictive_scorer.score(forecast)
        if epss_score is not None:
            scored.epss_scores = [epss_score]
        scored.suspected_actors = suspected_actors

        # --- fused risk + narratives ---
        risk = self.risk.score(threat=scored, cve=cve, kev=kev)
        scored.severity = ThreatSeverity(risk.label.value)
        scored.summary = self.narratives.build(scored)
        scored.recommended_soc_actions = self.soc.recommend(scored, cve=cve, kev=kev)
        scored.changelog.append(
            "Predictive + reactive scoring applied (model "
            f"{forecast.model_version}, p={forecast.attack_probability:.2f}, "
            f"horizon={forecast.horizon.value})."
        )
        return scored

    def _mark_campaign_membership(
        self,
        threats: list[ThreatRecord],
        campaigns: list[CampaignCluster],
        *,
        cves_by_id: dict[str, CVERecord],
        kev_by_cve: dict[str, KEVRecord],
        source_items: list[SourceItem],
        ransomware_posts_30d: int,
        local_intrusion_pressure: float,
        signal_index: PredictionSignalIndex,
    ) -> list[ThreatRecord]:
        membership: dict[str, list[str]] = {}
        for cluster in campaigns:
            for tid in cluster.related_threat_ids:
                membership.setdefault(tid, []).append(cluster.campaign_id)
        updated: list[ThreatRecord] = []
        for threat in threats:
            ids = membership.get(threat.threat_id, [])
            if not ids:
                updated.append(threat)
                continue
            copy = threat.model_copy(deep=True)
            copy.campaign_ids = ids
            cve = cves_by_id.get(copy.related_cves[0]) if copy.related_cves else None
            kev = kev_by_cve.get(copy.related_cves[0]) if copy.related_cves else None
            copy = self._score_threat(
                copy,
                cve=cve,
                kev=kev,
                related_items=signal_index.source_items_for_cves(copy.related_cves),
                source_items=source_items,
                ransomware_posts_30d=ransomware_posts_30d,
                local_intrusion_pressure=local_intrusion_pressure,
                campaign_active=True,
                signal_index=signal_index,
            )
            copy.campaign_ids = ids
            if copy.attack_forecast is not None:
                # Keep the campaign explanation visible after active-campaign scoring.
                membership_note = "Campaign membership recognized."
                copy.attack_forecast = copy.attack_forecast.model_copy(
                    update={
                        "reasons": [*copy.attack_forecast.reasons, membership_note],
                    }
                )
            updated.append(copy)
        return updated

    def _items_by_cve(self, items: list[SourceItem]) -> dict[str, list[SourceItem]]:
        grouped: dict[str, list[SourceItem]] = {}
        for item in items:
            cve_ids = self.extractor.extract(f"{item.title} {item.raw_content}").cve_ids
            for cve_id in cve_ids:
                grouped.setdefault(cve_id, []).append(item)
        return grouped
