"""Report the runtime's post-quantum cryptographic posture.

Surfaced by ``gn doctor crypto`` and the safety self-check. The goal is an
*honest* readout: what the engine can do today, what it would gain from the
``pq`` extra, and where the linked TLS stack stands on hybrid key exchange.
"""

from __future__ import annotations

import ssl

from pydantic import BaseModel, ConfigDict, Field

from greynoc_detector_engine.crypto import kem
from greynoc_detector_engine.crypto.signing import (
    ed25519_available,
    lms_available,
    mldsa_available,
)
from greynoc_detector_engine.utils.hashing import (
    DEFAULT_HASH_ALGORITHM,
    is_quantum_resistant_hash,
)

# OpenSSL gained the X25519MLKEM768 hybrid key-exchange group in 3.5.0.
_HYBRID_KEM_OPENSSL_MIN = (3, 5, 0)


class CryptoPosture(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hash_algorithm: str
    hash_quantum_resistant: bool
    hmac_signing: bool  # symmetric integrity baseline, always available
    lms_signing: bool  # post-quantum hash-based signing (stdlib, always available)
    ed25519_signing: bool  # classical asymmetric (optional)
    mldsa_signing: bool  # post-quantum lattice asymmetric (optional, liboqs)
    hybrid_signing: bool  # a classical + a PQ asymmetric signature can coexist
    pq_non_repudiation: bool  # a PQ public-key signature (LMS or ML-DSA) is available
    kem_available: bool  # hybrid/classical artifact KEM encryption is available
    kem_quantum_safe: bool  # the KEM has a post-quantum (ML-KEM) leg
    openssl_version: str
    hybrid_tls_kem_likely: bool
    findings: list[tuple[str, str, str]] = Field(default_factory=list)  # (name, severity, detail)

    @property
    def ready(self) -> bool:
        """Quantum-ready when integrity is PQ-safe AND PQ non-repudiation exists."""
        return self.hash_quantum_resistant and self.hmac_signing and self.pq_non_repudiation


def _openssl_info() -> tuple[int, int, int]:
    info = ssl.OPENSSL_VERSION_INFO
    return (int(info[0]), int(info[1]), int(info[2]))


def crypto_posture() -> CryptoPosture:
    ed25519 = ed25519_available()
    mldsa = mldsa_available()
    lms = lms_available()  # pure stdlib -> always True
    pq_non_repudiation = lms or mldsa
    kem_posture = kem.kem_posture()
    kem_av = kem.kem_available()
    hash_pq = is_quantum_resistant_hash(DEFAULT_HASH_ALGORITHM)
    openssl = _openssl_info()
    hybrid_kem = openssl >= _HYBRID_KEM_OPENSSL_MIN

    findings: list[tuple[str, str, str]] = []
    findings.append(
        (
            "crypto.hash_default",
            "ok" if hash_pq else "warn",
            f"{DEFAULT_HASH_ALGORITHM} "
            + ("(quantum-resistant)" if hash_pq else "(NOT quantum-resistant)"),
        )
    )
    findings.append(
        (
            "crypto.integrity_signing",
            "ok",
            "HMAC-SHA256 detached signing available (stdlib, quantum-resistant integrity).",
        )
    )
    findings.append(
        (
            "crypto.pq_signing_lms",
            "ok",
            "LMS/HSS (RFC 8554 / NIST SP 800-208) post-quantum hash-based signing "
            "available (pure stdlib, no liboqs). Stateful: persist key state per signature.",
        )
    )
    findings.append(
        (
            "crypto.pq_signing_mldsa",
            "ok" if mldsa else "warn",
            (
                "ML-DSA-65 (FIPS-204) lattice public-key signing available."
                if mldsa
                else "ML-DSA (lattice) unavailable; install the 'pq-mldsa' extra + liboqs "
                "(oqs) for an additional PQ backend. LMS/HSS already provides PQ "
                "non-repudiation."
            ),
        )
    )
    findings.append(
        (
            "crypto.pq_non_repudiation",
            "ok" if pq_non_repudiation else "warn",
            (
                "Post-quantum public-key non-repudiation available "
                f"({'LMS/HSS + ML-DSA' if (lms and mldsa) else 'LMS/HSS'})."
                if pq_non_repudiation
                else "No post-quantum public-key signature available."
            ),
        )
    )
    findings.append(
        (
            "crypto.hybrid_signing",
            "ok" if (ed25519 and pq_non_repudiation) else "warn",
            (
                "Hybrid classical + post-quantum signing available "
                "(Ed25519 + LMS/ML-DSA) -- the CNSA-2.0 migration posture."
                if (ed25519 and pq_non_repudiation)
                else "Hybrid signing needs 'cryptography' (Ed25519) alongside a PQ backend "
                "(LMS is always present; install 'pq' for Ed25519)."
            ),
        )
    )
    findings.append(
        (
            "crypto.artifact_kem",
            "ok" if kem_posture.quantum_safe else "warn",
            (
                "Hybrid X25519 + ML-KEM-768 authenticated artifact encryption available "
                "(post-quantum confidentiality)."
                if kem_posture.quantum_safe
                else (
                    "Artifact encryption available but classical X25519-only (no ML-KEM "
                    "backend); install 'pq-mldsa' (liboqs) or 'pq-pure' for PQ confidentiality."
                    if kem_av
                    else "Artifact KEM encryption needs 'cryptography' (X25519 + AES-GCM)."
                )
            ),
        )
    )
    findings.append(
        (
            "crypto.tls_hybrid_kem",
            "ok" if hybrid_kem else "warn",
            (
                f"{ssl.OPENSSL_VERSION}: linked OpenSSL is new enough for hybrid "
                "key exchange (X25519MLKEM768). Actual support depends on build flags."
                if hybrid_kem
                else f"{ssl.OPENSSL_VERSION}: predates OpenSSL 3.5; no hybrid TLS key "
                "exchange. Harvest-now-decrypt-later risk for live fetches over TLS."
            ),
        )
    )

    return CryptoPosture(
        hash_algorithm=DEFAULT_HASH_ALGORITHM,
        hash_quantum_resistant=hash_pq,
        hmac_signing=True,
        lms_signing=lms,
        ed25519_signing=ed25519,
        mldsa_signing=mldsa,
        hybrid_signing=ed25519 and pq_non_repudiation,
        pq_non_repudiation=pq_non_repudiation,
        kem_available=kem_av,
        kem_quantum_safe=kem_posture.quantum_safe,
        openssl_version=ssl.OPENSSL_VERSION,
        hybrid_tls_kem_likely=hybrid_kem,
        findings=findings,
    )
