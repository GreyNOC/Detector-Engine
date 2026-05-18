from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from greynoc_detector_engine.analysis.trend import TrendChange, TrendEngine
from greynoc_detector_engine.enrich.epss import EPSSEnricher
from greynoc_detector_engine.enrich.reputation import (
    IndicatorReputationEngine,
    ReputationVerdict,
)
from greynoc_detector_engine.enrich.threat_actor import ThreatActorAttributor
from greynoc_detector_engine.models.cve import CVERecord
from greynoc_detector_engine.models.kev import KEVRecord
from greynoc_detector_engine.models.prediction import EPSSScore, PredictionSignal
from greynoc_detector_engine.models.source import SourceItem
from greynoc_detector_engine.models.threat import ThreatRecord
from greynoc_detector_engine.utils.time import utc_now


class PredictiveContext(BaseModel):
    """Bundled inputs needed to score a single threat predictively."""

    model_config = ConfigDict(extra="forbid")

    threat: ThreatRecord
    cve: CVERecord | None = None
    kev: KEVRecord | None = None
    epss: EPSSScore | None = None
    source_items: list[SourceItem] = Field(default_factory=list)
    suspected_actors: list[str] = Field(default_factory=list)
    campaign_active: bool = False
    ransomware_claims_last_30d: int = 0
    sectors_in_play: list[str] = Field(default_factory=list)
    indexed_signal: PredictionSignal | None = None
    # Live local-sensor signal in [0, 1]; the correlation engine fills this in
    # from recent IntrusionSignal records affecting matched assets.
    local_intrusion_pressure: float = 0.0


class PredictiveFeatures(BaseModel):
    """The feature vector we score against. Every field is bounded to [0,1]
    so weights from the YAML config are interpretable and explainable."""

    model_config = ConfigDict(extra="forbid")

    epss_probability: float = Field(default=0.0, ge=0.0, le=1.0)
    epss_percentile: float = Field(default=0.0, ge=0.0, le=1.0)
    kev_listed: float = Field(default=0.0, ge=0.0, le=1.0)
    cvss_pressure: float = Field(default=0.0, ge=0.0, le=1.0)
    public_exploit_availability: float = Field(default=0.0, ge=0.0, le=1.0)
    chatter_velocity: float = Field(default=0.0, ge=0.0, le=1.0)
    independent_source_diversity: float = Field(default=0.0, ge=0.0, le=1.0)
    trusted_source_corroboration: float = Field(default=0.0, ge=0.0, le=1.0)
    ransomware_proximity: float = Field(default=0.0, ge=0.0, le=1.0)
    actor_activity: float = Field(default=0.0, ge=0.0, le=1.0)
    active_campaign: float = Field(default=0.0, ge=0.0, le=1.0)
    osint_ioc_corroboration: float = Field(default=0.0, ge=0.0, le=1.0)
    ai_attack_relevance: float = Field(default=0.0, ge=0.0, le=1.0)
    recency: float = Field(default=0.0, ge=0.0, le=1.0)
    local_intrusion_pressure: float = Field(default=0.0, ge=0.0, le=1.0)

    def as_dict(self) -> dict[str, float]:
        return self.model_dump()


class PredictiveFeatureBuilder:
    """Compute the bounded feature vector for one PredictiveContext."""

    def __init__(
        self,
        *,
        reputation: IndicatorReputationEngine | None = None,
        actor_attributor: ThreatActorAttributor | None = None,
        epss: EPSSEnricher | None = None,
    ) -> None:
        self.reputation = reputation or IndicatorReputationEngine()
        self.actor_attributor = actor_attributor or ThreatActorAttributor()
        self.epss = epss or EPSSEnricher()
        self.trend = TrendEngine()

    def build(self, ctx: PredictiveContext) -> PredictiveFeatures:
        return PredictiveFeatures(
            epss_probability=self._epss_probability(ctx),
            epss_percentile=self._epss_percentile(ctx),
            kev_listed=1.0 if ctx.kev is not None else 0.0,
            cvss_pressure=self._cvss_pressure(ctx),
            public_exploit_availability=self._exploit_availability(ctx),
            chatter_velocity=self._chatter_velocity(ctx),
            independent_source_diversity=self._source_diversity(ctx),
            trusted_source_corroboration=self._trusted_corroboration(ctx),
            ransomware_proximity=self._ransomware_proximity(ctx),
            actor_activity=self._actor_activity(ctx),
            active_campaign=1.0 if ctx.campaign_active else 0.0,
            osint_ioc_corroboration=self._osint_ioc_corroboration(ctx),
            ai_attack_relevance=1.0 if ctx.threat.ai_attack_type is not None else 0.0,
            recency=self._recency(ctx),
            local_intrusion_pressure=max(0.0, min(1.0, ctx.local_intrusion_pressure)),
        )

    @staticmethod
    def _epss_probability(ctx: PredictiveContext) -> float:
        return float(ctx.epss.epss) if ctx.epss else 0.0

    @staticmethod
    def _epss_percentile(ctx: PredictiveContext) -> float:
        return float(ctx.epss.percentile) if ctx.epss else 0.0

    @staticmethod
    def _cvss_pressure(ctx: PredictiveContext) -> float:
        if ctx.cve and ctx.cve.cvss_score is not None:
            return min(1.0, ctx.cve.cvss_score / 10.0)
        return 0.0

    @staticmethod
    def _exploit_availability(ctx: PredictiveContext) -> float:
        if not ctx.cve or not ctx.cve.exploit_references:
            return 0.0
        return min(1.0, len(ctx.cve.exploit_references) / 4.0)

    def _chatter_velocity(self, ctx: PredictiveContext) -> float:
        if ctx.indexed_signal is not None:
            return ctx.indexed_signal.chatter_velocity
        if not ctx.source_items or not ctx.threat.related_cves:
            return 0.0
        keys = [cve.lower() for cve in ctx.threat.related_cves]
        changes: list[TrendChange] = self.trend.detect_velocity_changes(ctx.source_items, keys)
        if not changes:
            return 0.0
        normalized = [
            self.trend.normalized_velocity(c.short_velocity, c.long_velocity) for c in changes
        ]
        return float(max(normalized))

    @staticmethod
    def _source_diversity(ctx: PredictiveContext) -> float:
        if ctx.indexed_signal is not None:
            return min(1.0, ctx.indexed_signal.source_diversity / 5.0)
        if not ctx.threat.source_references:
            return 0.0
        unique = {ref.source for ref in ctx.threat.source_references}
        return min(1.0, len(unique) / 5.0)

    @staticmethod
    def _trusted_corroboration(ctx: PredictiveContext) -> float:
        if ctx.indexed_signal is not None:
            return min(1.0, ctx.indexed_signal.trusted_source_count / 3.0)
        if not ctx.threat.source_references:
            return 0.0
        trusted = sum(1 for ref in ctx.threat.source_references if ref.confidence >= 0.8)
        return min(1.0, trusted / 3.0)

    @staticmethod
    def _ransomware_proximity(ctx: PredictiveContext) -> float:
        score = 0.0
        if ctx.kev and ctx.kev.known_ransomware_campaign_use == "Known":
            score = max(score, 0.8)
        if ctx.ransomware_claims_last_30d > 0:
            score = max(score, min(1.0, ctx.ransomware_claims_last_30d / 20.0))
        text = " ".join(
            [
                ctx.threat.summary,
                *(ref.raw_excerpt for ref in ctx.threat.source_references),
            ]
        ).lower()
        if "ransomware" in text:
            score = max(score, 0.5)
        return score

    @staticmethod
    def _actor_activity(ctx: PredictiveContext) -> float:
        if not ctx.suspected_actors:
            return 0.0
        # More distinct actors discussing the same threat = higher activity
        return min(1.0, 0.35 + 0.15 * len(ctx.suspected_actors))

    def _osint_ioc_corroboration(self, ctx: PredictiveContext) -> float:
        if not ctx.threat.observed_indicators:
            return 0.0
        confirmed = 0
        for indicator in ctx.threat.observed_indicators:
            verdict = self.reputation.lookup(indicator)
            if verdict.verdict == ReputationVerdict.MALICIOUS:
                confirmed += 1
        return min(1.0, confirmed / 3.0)

    @staticmethod
    def _recency(ctx: PredictiveContext) -> float:
        anchor: datetime | None = ctx.threat.last_seen or ctx.threat.first_seen
        if anchor is None:
            return 0.0
        delta_days = max(0.0, (utc_now() - anchor).total_seconds() / 86400.0)
        # 1.0 today, ~0.6 at one week, ~0.2 at one month, ~0.0 at three months
        return float(max(0.0, 1.0 - (delta_days / 90.0)))
