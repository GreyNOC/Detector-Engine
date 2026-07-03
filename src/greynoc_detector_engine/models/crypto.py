"""Schemas for the post-quantum crypto-posture domain.

These models are shared across the PQC analysis layer -- the crypto-inventory
scanner, the Mosca harvest-now-decrypt-later calculator, the CBOM emitter, and
the migration planner. They describe *other systems'* cryptography (the threat
side), distinct from :mod:`greynoc_detector_engine.models.quantum`, which scores
free-text threat reports.

Algorithm facts (quantum exposure, sizes, deprecation dates, replacements) come
from :mod:`greynoc_detector_engine.crypto.algorithms`, so :meth:`CryptoAsset.
from_algorithm` is the canonical way to build a recognized asset.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from greynoc_detector_engine.crypto import algorithms
from greynoc_detector_engine.crypto.algorithms import CryptoFamily, QuantumThreat
from greynoc_detector_engine.utils.time import utc_now


class CryptoAssetKind(StrEnum):
    ALGORITHM = "algorithm"
    CERTIFICATE = "certificate"
    PROTOCOL = "protocol"
    LIBRARY = "library"
    KEY = "key"
    TOKEN = "token"


class CryptoAsset(BaseModel):
    """One cryptographic asset discovered in some system, with its PQ posture."""

    model_config = ConfigDict(extra="forbid")

    identifier: str  # human label, e.g. "TLS cert for api.example.com" or "RSA-2048"
    kind: CryptoAssetKind = CryptoAssetKind.ALGORITHM
    algorithm: str | None = None  # canonical registry name if recognized
    parameter_set: str | None = None
    family: CryptoFamily | None = None
    quantum_threat: QuantumThreat | None = None  # None == unrecognized algorithm
    quantum_vulnerable: bool = False  # Shor-broken
    harvest_now_decrypt_later: bool = False  # confidentiality primitive -> recordable today
    nist_quantum_category: int = Field(default=0, ge=0, le=6)  # CycloneDX 0..6 scale
    classical_bits: int | None = None
    deprecated_after: int | None = None  # NIST IR 8547
    disallowed_after: int | None = None
    recommended_replacement: list[str] = Field(default_factory=list)
    location: str | None = None  # where it was found (host, file, config key)
    source: str | None = None  # inventory entry / scanner that produced it
    notes: list[str] = Field(default_factory=list)

    @classmethod
    def from_algorithm(
        cls,
        name: str,
        *,
        identifier: str | None = None,
        kind: CryptoAssetKind = CryptoAssetKind.ALGORITHM,
        location: str | None = None,
        source: str | None = None,
    ) -> CryptoAsset:
        """Build an asset from the registry; falls back to an unrecognized asset."""
        record = algorithms.get(name)
        if record is None:
            return cls(
                identifier=identifier or name,
                kind=kind,
                algorithm=None,
                location=location,
                source=source,
                notes=[f"{name!r} is not in the algorithm registry."],
            )
        return cls(
            identifier=identifier or record.name,
            kind=kind,
            algorithm=record.name,
            family=record.family,
            quantum_threat=record.quantum_threat,
            quantum_vulnerable=record.quantum_vulnerable,
            harvest_now_decrypt_later=record.quantum_vulnerable and record.confidentiality,
            nist_quantum_category=record.nist_category,
            classical_bits=record.classical_bits,
            deprecated_after=record.deprecated_after,
            disallowed_after=record.disallowed_after,
            recommended_replacement=list(record.replaces_with),
            location=location,
            source=source,
        )


class MoscaAssessment(BaseModel):
    """Mosca's inequality: are we already too late to protect this data?

    With X = data security shelf-life, Y = migration time, Z = years until a
    cryptographically-relevant quantum computer, the data is *already at risk*
    when ``X + Y >= Z`` (the formal statement uses ``>``; we use ``>=`` as the
    conservative planning boundary).
    """

    model_config = ConfigDict(extra="forbid")

    data_shelf_life_years: float = Field(ge=0)  # X
    migration_years: float = Field(ge=0)  # Y
    crqc_years: float = Field(ge=0)  # Z
    at_risk: bool
    margin_years: float  # Z - (X + Y); negative means already exposed
    max_migration_years: float  # Z - X; the migration budget before exposure
    rationale: list[str] = Field(default_factory=list)
    assessed_at: datetime = Field(default_factory=utc_now)


class MigrationUrgency(StrEnum):
    IMMEDIATE = "immediate"  # HNDL + long shelf-life: act now
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"  # already quantum-safe


class MigrationItem(BaseModel):
    """One asset's place in the migration plan."""

    model_config = ConfigDict(extra="forbid")

    asset: CryptoAsset
    urgency: MigrationUrgency
    priority_score: float = Field(ge=0.0, le=1.0)
    target_algorithms: list[str] = Field(default_factory=list)
    deadline_year: int | None = None
    mosca: MoscaAssessment | None = None
    rationale: list[str] = Field(default_factory=list)


class MigrationPlan(BaseModel):
    """A prioritized post-quantum migration plan over a crypto inventory."""

    model_config = ConfigDict(extra="forbid")

    items: list[MigrationItem] = Field(default_factory=list)
    total_assets: int = 0
    immediate: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    already_safe: int = 0
    generated_at: datetime = Field(default_factory=utc_now)
    methodology: str = (
        "Assets are ranked by harvest-now-decrypt-later exposure, Mosca margin, "
        "and NIST IR 8547 / CNSA 2.0 deadlines. Glass-box and offline."
    )
    summary: list[str] = Field(default_factory=list)


class CryptoPostureSummary(BaseModel):
    """Aggregate quantum posture of a crypto inventory."""

    model_config = ConfigDict(extra="forbid")

    total_assets: int
    quantum_vulnerable: int
    quantum_safe: int
    unrecognized: int
    harvest_now_decrypt_later: int
    by_family: dict[str, int] = Field(default_factory=dict)
    by_threat: dict[str, int] = Field(default_factory=dict)
    readiness_score: float = Field(ge=0.0, le=1.0)  # 1.0 == fully quantum-safe
    findings: list[str] = Field(default_factory=list)
    assessed_at: datetime = Field(default_factory=utc_now)


class KeyState(StrEnum):
    ACTIVE = "active"
    RETIRED = "retired"
    COMPROMISED = "compromised"
    EXHAUSTED = "exhausted"  # stateful HBS: all one-time keys consumed


class KeyMetadata(BaseModel):
    """Public, auditable metadata for a managed signing/KEM key (no secret bytes)."""

    model_config = ConfigDict(extra="forbid")

    key_id: str
    algorithm: str
    quantum_safe: bool
    state: KeyState = KeyState.ACTIVE
    created_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime | None = None
    rotated_from: str | None = None  # prior key_id this one supersedes
    public_key: str | None = None  # base64; present for asymmetric keys
    signatures_remaining: int | None = None  # stateful HBS budget; None == unlimited
    usage: list[str] = Field(default_factory=list)  # e.g. ["sign", "verify"]
    notes: list[str] = Field(default_factory=list)
