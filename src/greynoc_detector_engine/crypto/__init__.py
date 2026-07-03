"""Crypto-agility layer: hybrid post-quantum artifact signing, KEM, and posture.

The detection engine publishes artifacts a downstream consumer must be able to
trust were not tampered with in transit or at rest -- generated detection
bundles, STIX 2.1 exports, and threat snapshots. This package signs those
artifacts with a **crypto-agile, hybrid** scheme, can **encrypt** them with a
hybrid KEM, and reports the runtime's post-quantum posture honestly.

Design (chosen so the engine stays offline-first and dependency-light):

  * **Always on (stdlib):** an HMAC-SHA256 detached signature (symmetric,
    quantum-resistant integrity) **and** LMS/HSS hash-based public-key signatures
    (RFC 8554 / NIST SP 800-208, :mod:`greynoc_detector_engine.crypto.hbs`) --
    real post-quantum *non-repudiation* with no optional dependency.
  * **Optional (the ``pq`` / ``pq-mldsa`` / ``pq-pure`` extras):** classical
    Ed25519 (``cryptography``), the FIPS-204 ML-DSA lattice signature (``oqs`` /
    liboqs), and ML-KEM key encapsulation (``oqs`` or pure-python ``kyber_py``).
    When a classical and a PQ asymmetric signature coexist the envelope is a true
    *hybrid* -- the NIST/CNSA-2.0 migration recommendation.

The authoritative algorithm facts (sizes, categories, standards, deprecation
dates) live in :mod:`greynoc_detector_engine.crypto.algorithms`. Optional
backends are import-guarded; the signer/KEM degrade gracefully and
:func:`crypto_posture` reports exactly what is active.
"""

from __future__ import annotations

from greynoc_detector_engine.crypto.kem import (
    HybridKemKeypair,
    KemEnvelope,
    KemPosture,
    decrypt,
    encrypt,
    generate_kem_keypair,
    kem_available,
    kem_posture,
    mlkem_available,
    x25519_available,
)
from greynoc_detector_engine.crypto.posture import CryptoPosture, crypto_posture
from greynoc_detector_engine.crypto.signing import (
    ALG_ED25519,
    ALG_HMAC,
    ALG_LMS,
    ALG_MLDSA,
    HybridSigner,
    SignatureComponent,
    SignatureEnvelope,
    SigningKeyset,
    VerificationResult,
    ed25519_available,
    generate_keyset,
    keyset_from_hmac_secret,
    lms_available,
    mldsa_available,
)

__all__ = [
    "ALG_ED25519",
    "ALG_HMAC",
    "ALG_LMS",
    "ALG_MLDSA",
    "CryptoPosture",
    "HybridKemKeypair",
    "HybridSigner",
    "KemEnvelope",
    "KemPosture",
    "SignatureComponent",
    "SignatureEnvelope",
    "SigningKeyset",
    "VerificationResult",
    "crypto_posture",
    "decrypt",
    "ed25519_available",
    "encrypt",
    "generate_kem_keypair",
    "generate_keyset",
    "kem_available",
    "kem_posture",
    "keyset_from_hmac_secret",
    "lms_available",
    "mldsa_available",
    "mlkem_available",
    "x25519_available",
]
