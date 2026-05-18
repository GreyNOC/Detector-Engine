from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from greynoc_detector_engine.utils.time import utc_now


class ForecastHorizon(StrEnum):
    """Coarse time bucket within which an attack is forecast to materialize."""

    IMMINENT = "imminent"  # 0-7 days
    NEAR_TERM = "near_term"  # 8-30 days
    MID_TERM = "mid_term"  # 31-90 days
    LONG_TERM = "long_term"  # 91+ days
    UNLIKELY = "unlikely"  # baseline / no signal


class ConfidenceBand(StrEnum):
    """Confidence in the prediction, distinct from probability of the event."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class PredictionDriver(BaseModel):
    """A single, named factor that pushed the prediction up or down."""

    model_config = ConfigDict(extra="forbid")

    name: str
    weight: float = Field(ge=-1.0, le=1.0)
    value: float = Field(ge=0.0, le=1.0)
    contribution: float
    rationale: str


class AttackForecast(BaseModel):
    """Forward-looking, explainable attack forecast for a threat record."""

    model_config = ConfigDict(extra="forbid")

    attack_probability: float = Field(ge=0.0, le=1.0)
    horizon: ForecastHorizon
    horizon_days_p50: int = Field(ge=0)
    horizon_days_p90: int = Field(ge=0)
    confidence: ConfidenceBand
    drivers: list[PredictionDriver] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    osint_signal_count: int = Field(default=0, ge=0)
    independent_corroborations: int = Field(default=0, ge=0)
    model_version: str = "horizon-1.0"
    generated_at: datetime = Field(default_factory=utc_now)


class PredictionSignal(BaseModel):
    """Precomputed source-signal features for one or more related CVEs."""

    model_config = ConfigDict(extra="forbid")

    cve_ids: list[str] = Field(default_factory=list)
    source_item_ids: list[str] = Field(default_factory=list)
    source_ids: list[str] = Field(default_factory=list)
    source_diversity: int = Field(default=0, ge=0)
    trusted_source_count: int = Field(default=0, ge=0)
    cve_mention_count: int = Field(default=0, ge=0)
    chatter_velocity: float = Field(default=0.0, ge=0.0, le=1.0)
    raw_items_scanned: int = Field(default=0, ge=0)


class PredictionFingerprint(BaseModel):
    """Input fingerprint used to skip unchanged forecast recomputation."""

    model_config = ConfigDict(extra="forbid")

    threat_id: str
    fingerprint: str
    model_version: str
    source_watermark: str
    reputation_watermark: str
    config_hash: str
    updated_at: datetime = Field(default_factory=utc_now)


class ForecastRun(BaseModel):
    """Operational metrics captured for a predictive run."""

    model_config = ConfigDict(extra="forbid")

    run_id: int | None = None
    started_at: datetime
    ended_at: datetime
    duration_seconds: float = Field(ge=0.0)
    threat_count: int = Field(ge=0)
    raw_item_count: int = Field(ge=0)
    skipped_count: int = Field(ge=0)
    write_count: int = Field(ge=0)
    model_version: str
    model_config_hash: str
    threats_per_second: float = Field(ge=0.0)
    raw_items_scanned: int = Field(ge=0)
    forecast_latency_p95: float = Field(ge=0.0)
    brier_score: float = Field(default=0.0, ge=0.0, le=1.0)
    precision_at_n: dict[str, float] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)


class EPSSScore(BaseModel):
    """FIRST.org Exploit Prediction Scoring System point."""

    model_config = ConfigDict(extra="forbid")

    cve_id: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$")
    epss: float = Field(ge=0.0, le=1.0)
    percentile: float = Field(ge=0.0, le=1.0)
    score_date: datetime
    source: str = "FIRST.org EPSS"


class ThreatActorProfile(BaseModel):
    """Light-weight threat-actor signal, attributed from public reporting."""

    model_config = ConfigDict(extra="forbid")

    actor_id: str
    aliases: list[str] = Field(default_factory=list)
    motivation: str | None = None
    sectors_targeted: list[str] = Field(default_factory=list)
    countries_targeted: list[str] = Field(default_factory=list)
    known_ttps: list[str] = Field(default_factory=list)
    mitre_attack_techniques: list[str] = Field(default_factory=list)
    known_tools: list[str] = Field(default_factory=list)
    last_observed: datetime | None = None
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)


class CampaignCluster(BaseModel):
    """Inferred attack campaign clustering related threats together."""

    model_config = ConfigDict(extra="forbid")

    campaign_id: str
    label: str
    related_threat_ids: list[str] = Field(default_factory=list)
    related_cves: list[str] = Field(default_factory=list)
    suspected_actors: list[str] = Field(default_factory=list)
    shared_indicators: list[str] = Field(default_factory=list)
    affected_sectors: list[str] = Field(default_factory=list)
    affected_products: list[str] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    velocity_score: float = Field(default=0.0, ge=0.0, le=1.0)
    cohesion: float = Field(default=0.0, ge=0.0, le=1.0)
    reasons: list[str] = Field(default_factory=list)


class VelocityBaseline(BaseModel):
    """Statistical baseline of chatter for a given key (CVE / product / term)."""

    model_config = ConfigDict(extra="forbid")

    key: str
    window_days: int = Field(ge=1)
    baseline_mean: float = Field(ge=0.0)
    baseline_std: float = Field(ge=0.0)
    observed: int = Field(ge=0)
    z_score: float
    is_anomalous: bool
    observed_at: datetime = Field(default_factory=utc_now)
