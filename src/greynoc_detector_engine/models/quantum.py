"""Schema for the post-quantum / harvest-now-decrypt-later threat dimension.

A *detection* engine should not only protect its own artifacts with PQ crypto;
it should also recognise and prioritise threats to **other systems'** crypto as
the migration to post-quantum standards (NIST FIPS 203/204/205, CNSA 2.0) gets
underway. This schema captures that assessment for a threat record.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from greynoc_detector_engine.utils.time import utc_now


class QuantumRiskLevel(StrEnum):
    NONE = "none"
    LOW = "low"  # quantum/PQC discussion, no concrete vulnerable primitive
    MODERATE = "moderate"  # signature-only exposure (forgery needs a CRQC at attack time)
    HIGH = "high"  # confidentiality primitive exposed -> harvest-now-decrypt-later
    CRITICAL = "critical"  # HNDL plus explicit harvest / CRQC / Q-Day context


class QuantumRiskAssessment(BaseModel):
    """Explainable post-quantum exposure assessment for a threat."""

    model_config = ConfigDict(extra="forbid")

    risk_level: QuantumRiskLevel
    score: float = Field(ge=0.0, le=1.0)
    quantum_vulnerable: bool
    harvest_now_decrypt_later: bool
    cnsa_2_0_relevant: bool
    affected_primitives: list[str] = Field(default_factory=list)
    matched_terms: list[str] = Field(default_factory=list)
    rationale: list[str] = Field(default_factory=list)
    assessed_at: datetime = Field(default_factory=utc_now)
