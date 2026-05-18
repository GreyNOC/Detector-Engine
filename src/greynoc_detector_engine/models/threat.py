from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from greynoc_detector_engine.models.detection import GeneratedDetection
from greynoc_detector_engine.models.indicator import Indicator
from greynoc_detector_engine.models.prediction import AttackForecast, EPSSScore
from greynoc_detector_engine.models.scoring import ScoreResult
from greynoc_detector_engine.models.source import SourceReference


class ThreatStatus(StrEnum):
    NEW = "new"
    MONITORING = "monitoring"
    VALIDATED = "validated"
    DEPRECATED = "deprecated"


class ThreatSeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AIAttackType(StrEnum):
    PROMPT_INJECTION = "prompt_injection"
    INDIRECT_PROMPT_INJECTION = "indirect_prompt_injection"
    MODEL_JAILBREAK = "model_jailbreak"
    MODEL_EXTRACTION = "model_extraction"
    DATA_POISONING = "data_poisoning"
    TRAINING_DATA_LEAKAGE = "training_data_leakage"
    RAG_POISONING = "retrieval_augmented_generation_poisoning"
    TOOL_USE_ABUSE = "tool_use_abuse"
    AGENT_HIJACKING = "agent_hijacking"
    AI_SUPPLY_CHAIN_COMPROMISE = "ai_supply_chain_compromise"
    MALICIOUS_MODEL_UPLOAD = "malicious_model_upload"
    MALICIOUS_AI_PACKAGE = "malicious_ai_package_or_dependency"
    DEEPFAKE_SOCIAL_ENGINEERING = "deepfake_enabled_social_engineering"
    AUTOMATED_PHISHING_GENERATION = "automated_phishing_generation"
    AI_ASSISTED_VULNERABILITY_DISCOVERY = "ai_assisted_vulnerability_discovery"
    AI_ASSISTED_MALWARE_MUTATION = "ai_assisted_malware_mutation"
    AI_POWERED_CREDENTIAL_ATTACK = "ai_powered_credential_attack"
    AUTONOMOUS_RECON = "autonomous_recon_or_scanning_behavior"
    SYNTHETIC_IDENTITY_ABUSE = "synthetic_identity_abuse"
    UNKNOWN_AI_ENABLED_TECHNIQUE = "unknown_ai_enabled_technique"


class ThreatRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    threat_id: str = Field(default_factory=lambda: f"thr-{uuid4().hex[:12]}")
    title: str
    summary: str
    category: str
    ai_attack_type: AIAttackType | None = None
    affected_products: list[str] = Field(default_factory=list)
    related_cves: list[str] = Field(default_factory=list)
    related_kev_entries: list[str] = Field(default_factory=list)
    observed_indicators: list[Indicator] = Field(default_factory=list)
    tactics_techniques_procedures: list[str] = Field(default_factory=list)
    mitre_attack_mapping: list[str] = Field(default_factory=list)
    source_references: list[SourceReference] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    confidence: float = Field(default=0.5, ge=0, le=1)
    severity: ThreatSeverity = ThreatSeverity.MEDIUM
    exploitability_score: ScoreResult | None = None
    early_warning_score: ScoreResult | None = None
    ai_abuse_score: ScoreResult | None = None
    predictive_score: ScoreResult | None = None
    attack_forecast: AttackForecast | None = None
    epss_scores: list[EPSSScore] = Field(default_factory=list)
    suspected_actors: list[str] = Field(default_factory=list)
    campaign_ids: list[str] = Field(default_factory=list)
    sectors_at_risk: list[str] = Field(default_factory=list)
    recommended_soc_actions: list[str] = Field(default_factory=list)
    detection_opportunities: list[str] = Field(default_factory=list)
    generated_detections: list[GeneratedDetection] = Field(default_factory=list)
    status: ThreatStatus = ThreatStatus.NEW
    version: int = 1
    changelog: list[str] = Field(default_factory=list)
