"""Authoritative registry of cryptographic algorithms and their quantum posture.

This module is the **single source of truth** for the whole post-quantum layer.
Which primitives a cryptographically-relevant quantum computer (CRQC) breaks,
their NIST PQC security category, byte sizes, governing standard, and the
CNSA-2.0 / NIST IR 8547 migration deadlines are defined here exactly once.
Posture reporting, the quantum-risk classifier, CBOM emission, the crypto
inventory scanner, and the migration planner all read their facts from here, so
a size, date, or category is never duplicated (or allowed to drift) elsewhere.

Every number below is transcribed from a primary standard:

  * **FIPS 203** (ML-KEM), **FIPS 204** (ML-DSA), **FIPS 205** (SLH-DSA) -- the
    finalized NIST PQC standards (published 2024-08-13).
  * **RFC 8554** / **NIST SP 800-208** -- LMS/HSS stateful hash-based signatures.
  * **RFC 8391** -- XMSS / XMSS^MT.
  * **NIST IR 8547 ipd** -- the classical-public-key deprecation timeline
    (112-bit deprecated after 2030, disallowed after 2035; >=128-bit disallowed
    after 2035).
  * **NSA CNSA 2.0** -- the suite of algorithms approved for national security
    systems and its transition timeline.

See ``docs/standards_reference.md`` for the full citation list.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class CryptoFamily(StrEnum):
    """What a primitive is *for* -- the axis that decides quantum exposure."""

    KEM = "kem"  # key encapsulation (confidentiality)
    KEY_AGREEMENT = "key-agreement"  # (EC)DH -- confidentiality
    PUBLIC_KEY_ENCRYPTION = "public-key-encryption"  # RSA key transport
    SIGNATURE = "signature"  # authenticity / non-repudiation
    SYMMETRIC = "symmetric"  # block / stream cipher
    MAC = "mac"  # message authentication code
    HASH = "hash"  # digest / XOF


class QuantumThreat(StrEnum):
    """How a CRQC affects the primitive."""

    BROKEN = "broken"  # Shor: fully broken (RSA/ECC/DH) -- migrate
    WEAKENED = "weakened"  # Grover: strength ~halved, still adequate at >=256-bit
    SAFE = "safe"  # post-quantum design or hash-based -- quantum-resistant


class Standard(StrEnum):
    """Governing specification, used verbatim in posture / CBOM output."""

    FIPS_197 = "FIPS 197"  # AES
    FIPS_180_4 = "FIPS 180-4"  # SHA-2
    FIPS_202 = "FIPS 202"  # SHA-3 / SHAKE
    FIPS_186_5 = "FIPS 186-5"  # (EC)DSA / EdDSA
    FIPS_203 = "FIPS 203"  # ML-KEM
    FIPS_204 = "FIPS 204"  # ML-DSA
    FIPS_205 = "FIPS 205"  # SLH-DSA
    FIPS_206 = "FIPS 206 (draft)"  # FN-DSA / Falcon -- not yet finalized
    SP_800_208 = "NIST SP 800-208"  # LMS / XMSS (stateful HBS)
    SP_800_56A = "NIST SP 800-56A"  # (EC)DH key establishment
    SP_800_56B = "NIST SP 800-56B"  # RSA key establishment
    RFC_8554 = "RFC 8554"  # LMS / HSS
    RFC_8391 = "RFC 8391"  # XMSS / XMSS^MT
    RFC_8032 = "RFC 8032"  # Ed25519 / Ed448
    RFC_7748 = "RFC 7748"  # X25519 / X448
    PKCS1 = "PKCS#1"  # RSA


# ---------------------------------------------------------------------------
# Migration-policy constants (primary sources cited above)
# ---------------------------------------------------------------------------

# NSM-10: government-wide endpoint for migrating NSS off quantum-vulnerable crypto.
NSM10_ENDPOINT_YEAR = 2035
# CNSA 2.0: exclusive use of the suite across NSS.
CNSA_2_0_EXCLUSIVE_YEAR = 2033
# CNSA 2.0: new NSS acquisitions must support the suite from this date.
CNSA_2_0_ACQUISITION_GATE_YEAR = 2027

# CNSA 2.0 per-technology transition grid: class -> (support+prefer-by, exclusive-by).
CNSA_2_0_TIMELINE: dict[str, tuple[int, int]] = {
    "software_and_firmware_signing": (2025, 2030),
    "web_browsers_servers_cloud": (2025, 2033),
    "traditional_networking": (2026, 2030),
    "operating_systems": (2027, 2033),
    "niche_equipment": (2030, 2033),
    "custom_and_legacy": (2030, 2033),
}


@dataclass(frozen=True)
class AlgorithmRecord:
    """One algorithm (or parameter set) and everything the PQC layer needs."""

    name: str
    family: CryptoFamily
    quantum_threat: QuantumThreat
    standard: Standard | None = None
    nist_category: int = 0  # NIST PQC security category 0..5 (0 == none met / N/A)
    classical_bits: int | None = None  # classical security strength in bits
    public_key_bytes: int | None = None
    secret_key_bytes: int | None = None
    signature_bytes: int | None = None  # max for variable-length (e.g. Falcon)
    ciphertext_bytes: int | None = None
    shared_secret_bytes: int | None = None
    stateful: bool = False  # stateful HBS: one-time keys, reuse is catastrophic
    oid: str | None = None
    aliases: tuple[str, ...] = ()
    replaces_with: tuple[str, ...] = ()  # recommended PQ replacement algorithm names
    deprecated_after: int | None = None  # NIST IR 8547 "deprecated after" year
    disallowed_after: int | None = None  # NIST IR 8547 "disallowed after" year
    cnsa_2_0: bool = False  # member of the CNSA 2.0 suite
    notes: str = ""

    @property
    def quantum_safe(self) -> bool:
        """Survives a CRQC (not Shor-broken). Grover-weakened primitives count."""
        return self.quantum_threat is not QuantumThreat.BROKEN

    @property
    def quantum_vulnerable(self) -> bool:
        return self.quantum_threat is QuantumThreat.BROKEN

    @property
    def confidentiality(self) -> bool:
        """Whether breaking it exposes *recorded* data (harvest-now-decrypt-later)."""
        return self.family in (
            CryptoFamily.KEM,
            CryptoFamily.KEY_AGREEMENT,
            CryptoFamily.PUBLIC_KEY_ENCRYPTION,
            CryptoFamily.SYMMETRIC,
        )


def _sig(
    name: str,
    threat: QuantumThreat,
    standard: Standard,
    **kw: Any,
) -> AlgorithmRecord:
    return AlgorithmRecord(
        name=name, family=CryptoFamily.SIGNATURE, quantum_threat=threat, standard=standard, **kw
    )


# ---------------------------------------------------------------------------
# The registry
# ---------------------------------------------------------------------------

_PQ_SIG_GENERAL = ("ML-DSA-65",)
_PQ_SIG_HIGH = ("ML-DSA-87", "SLH-DSA-SHA2-256s")
_PQ_KEM_GENERAL = ("ML-KEM-768",)
_PQ_KEM_HIGH = ("ML-KEM-1024",)

_RECORDS: tuple[AlgorithmRecord, ...] = (
    # -- Post-quantum KEMs (FIPS 203) --------------------------------------
    AlgorithmRecord(
        "ML-KEM-512",
        CryptoFamily.KEM,
        QuantumThreat.SAFE,
        Standard.FIPS_203,
        nist_category=1,
        public_key_bytes=800,
        secret_key_bytes=1632,
        ciphertext_bytes=768,
        shared_secret_bytes=32,
        aliases=("Kyber512",),
    ),
    AlgorithmRecord(
        "ML-KEM-768",
        CryptoFamily.KEM,
        QuantumThreat.SAFE,
        Standard.FIPS_203,
        nist_category=3,
        public_key_bytes=1184,
        secret_key_bytes=2400,
        ciphertext_bytes=1088,
        shared_secret_bytes=32,
        aliases=("Kyber768",),
        notes="NIST-recommended default KEM.",
    ),
    AlgorithmRecord(
        "ML-KEM-1024",
        CryptoFamily.KEM,
        QuantumThreat.SAFE,
        Standard.FIPS_203,
        nist_category=5,
        public_key_bytes=1568,
        secret_key_bytes=3168,
        ciphertext_bytes=1568,
        shared_secret_bytes=32,
        aliases=("Kyber1024",),
        cnsa_2_0=True,
        notes="CNSA 2.0 key establishment.",
    ),
    # -- Post-quantum signatures (FIPS 204) --------------------------------
    _sig(
        "ML-DSA-44",
        QuantumThreat.SAFE,
        Standard.FIPS_204,
        nist_category=2,
        public_key_bytes=1312,
        secret_key_bytes=2560,
        signature_bytes=2420,
        aliases=("Dilithium2",),
    ),
    _sig(
        "ML-DSA-65",
        QuantumThreat.SAFE,
        Standard.FIPS_204,
        nist_category=3,
        public_key_bytes=1952,
        secret_key_bytes=4032,
        signature_bytes=3309,
        aliases=("Dilithium3",),
        notes="General-purpose PQ signature default.",
    ),
    _sig(
        "ML-DSA-87",
        QuantumThreat.SAFE,
        Standard.FIPS_204,
        nist_category=5,
        public_key_bytes=2592,
        secret_key_bytes=4896,
        signature_bytes=4627,
        aliases=("Dilithium5",),
        cnsa_2_0=True,
        notes="CNSA 2.0 general signature.",
    ),
    # -- Post-quantum signatures (FIPS 205, SLH-DSA) -----------------------
    # SHA2 and SHAKE variants share byte sizes; both registered with aliases.
    _sig(
        "SLH-DSA-SHA2-128s",
        QuantumThreat.SAFE,
        Standard.FIPS_205,
        nist_category=1,
        public_key_bytes=32,
        secret_key_bytes=64,
        signature_bytes=7856,
        aliases=("SLH-DSA-SHAKE-128s", "SPHINCS+-SHA2-128s-simple"),
    ),
    _sig(
        "SLH-DSA-SHA2-128f",
        QuantumThreat.SAFE,
        Standard.FIPS_205,
        nist_category=1,
        public_key_bytes=32,
        secret_key_bytes=64,
        signature_bytes=17088,
        aliases=("SLH-DSA-SHAKE-128f", "SPHINCS+-SHA2-128f-simple"),
    ),
    _sig(
        "SLH-DSA-SHA2-192s",
        QuantumThreat.SAFE,
        Standard.FIPS_205,
        nist_category=3,
        public_key_bytes=48,
        secret_key_bytes=96,
        signature_bytes=16224,
        aliases=("SLH-DSA-SHAKE-192s", "SPHINCS+-SHA2-192s-simple"),
    ),
    _sig(
        "SLH-DSA-SHA2-192f",
        QuantumThreat.SAFE,
        Standard.FIPS_205,
        nist_category=3,
        public_key_bytes=48,
        secret_key_bytes=96,
        signature_bytes=35664,
        aliases=("SLH-DSA-SHAKE-192f", "SPHINCS+-SHA2-192f-simple"),
    ),
    _sig(
        "SLH-DSA-SHA2-256s",
        QuantumThreat.SAFE,
        Standard.FIPS_205,
        nist_category=5,
        public_key_bytes=64,
        secret_key_bytes=128,
        signature_bytes=29792,
        aliases=("SLH-DSA-SHAKE-256s", "SPHINCS+-SHA2-256s-simple"),
    ),
    _sig(
        "SLH-DSA-SHA2-256f",
        QuantumThreat.SAFE,
        Standard.FIPS_205,
        nist_category=5,
        public_key_bytes=64,
        secret_key_bytes=128,
        signature_bytes=49856,
        aliases=("SLH-DSA-SHAKE-256f", "SPHINCS+-SHA2-256f-simple"),
    ),
    # -- Stateful hash-based signatures (RFC 8554 / SP 800-208) ------------
    _sig(
        "LMS-SHA256-M32-H10",
        QuantumThreat.SAFE,
        Standard.RFC_8554,
        nist_category=5,
        classical_bits=256,
        public_key_bytes=56,
        stateful=True,
        cnsa_2_0=True,
        aliases=("LMS", "HSS"),
        notes="Stateful: each one-time key signs exactly once. CNSA 2.0 firmware "
        "signing. Implemented in pure stdlib (greynoc...crypto.hbs).",
    ),
    _sig(
        "XMSS-SHA256-H10",
        QuantumThreat.SAFE,
        Standard.RFC_8391,
        nist_category=5,
        classical_bits=256,
        stateful=True,
        cnsa_2_0=True,
        aliases=("XMSS", "XMSSMT"),
        notes="Stateful hash-based signature; CNSA 2.0 firmware signing.",
    ),
    # -- Falcon / FN-DSA (FIPS 206, DRAFT -- sizes provisional) ------------
    _sig(
        "Falcon-512",
        QuantumThreat.SAFE,
        Standard.FIPS_206,
        nist_category=1,
        public_key_bytes=897,
        secret_key_bytes=1281,
        signature_bytes=752,
        aliases=("FN-DSA-512",),
        notes="FIPS 206 still draft; sizes provisional.",
    ),
    _sig(
        "Falcon-1024",
        QuantumThreat.SAFE,
        Standard.FIPS_206,
        nist_category=5,
        public_key_bytes=1793,
        secret_key_bytes=2305,
        signature_bytes=1462,
        aliases=("FN-DSA-1024",),
        notes="FIPS 206 still draft; sizes provisional.",
    ),
    # -- Classical signatures (Shor-broken) --------------------------------
    _sig(
        "RSA-2048",
        QuantumThreat.BROKEN,
        Standard.FIPS_186_5,
        classical_bits=112,
        oid="1.2.840.113549.1.1.1",
        replaces_with=_PQ_SIG_GENERAL,
        deprecated_after=2030,
        disallowed_after=2035,
    ),
    _sig(
        "RSA-3072",
        QuantumThreat.BROKEN,
        Standard.FIPS_186_5,
        classical_bits=128,
        oid="1.2.840.113549.1.1.1",
        replaces_with=_PQ_SIG_GENERAL,
        disallowed_after=2035,
    ),
    _sig(
        "RSA-4096",
        QuantumThreat.BROKEN,
        Standard.FIPS_186_5,
        classical_bits=152,
        oid="1.2.840.113549.1.1.1",
        replaces_with=_PQ_SIG_HIGH,
        disallowed_after=2035,
    ),
    _sig(
        "ECDSA-P256",
        QuantumThreat.BROKEN,
        Standard.FIPS_186_5,
        classical_bits=128,
        oid="1.2.840.10045.4.3.2",
        aliases=("ecdsa-with-SHA256", "prime256v1", "secp256r1"),
        replaces_with=_PQ_SIG_GENERAL,
        disallowed_after=2035,
    ),
    _sig(
        "ECDSA-P384",
        QuantumThreat.BROKEN,
        Standard.FIPS_186_5,
        classical_bits=192,
        aliases=("secp384r1",),
        replaces_with=_PQ_SIG_HIGH,
        disallowed_after=2035,
    ),
    _sig(
        "Ed25519",
        QuantumThreat.BROKEN,
        Standard.RFC_8032,
        classical_bits=128,
        oid="1.3.101.112",
        aliases=("EdDSA",),
        replaces_with=_PQ_SIG_GENERAL,
        disallowed_after=2035,
    ),
    # -- Classical key establishment (Shor-broken, harvest-now-decrypt-later) --
    AlgorithmRecord(
        "RSA-2048-KEX",
        CryptoFamily.PUBLIC_KEY_ENCRYPTION,
        QuantumThreat.BROKEN,
        Standard.SP_800_56B,
        classical_bits=112,
        oid="1.2.840.113549.1.1.1",
        aliases=("RSA key transport",),
        replaces_with=_PQ_KEM_GENERAL,
        deprecated_after=2030,
        disallowed_after=2035,
    ),
    AlgorithmRecord(
        "ECDH-P256",
        CryptoFamily.KEY_AGREEMENT,
        QuantumThreat.BROKEN,
        Standard.SP_800_56A,
        classical_bits=128,
        aliases=("ecdh", "secp256r1"),
        replaces_with=_PQ_KEM_GENERAL,
        disallowed_after=2035,
    ),
    AlgorithmRecord(
        "ECDH-P384",
        CryptoFamily.KEY_AGREEMENT,
        QuantumThreat.BROKEN,
        Standard.SP_800_56A,
        classical_bits=192,
        replaces_with=_PQ_KEM_HIGH,
        disallowed_after=2035,
    ),
    AlgorithmRecord(
        "X25519",
        CryptoFamily.KEY_AGREEMENT,
        QuantumThreat.BROKEN,
        Standard.RFC_7748,
        classical_bits=128,
        oid="1.3.101.110",
        aliases=("curve25519", "x25519"),
        replaces_with=_PQ_KEM_GENERAL,
        disallowed_after=2035,
        notes="Pair with ML-KEM-768 for a hybrid KEM (X25519MLKEM768).",
    ),
    AlgorithmRecord(
        "DH-2048",
        CryptoFamily.KEY_AGREEMENT,
        QuantumThreat.BROKEN,
        Standard.SP_800_56A,
        classical_bits=112,
        aliases=("finite-field DH", "FFDHE2048"),
        replaces_with=_PQ_KEM_GENERAL,
        deprecated_after=2030,
        disallowed_after=2035,
    ),
    AlgorithmRecord(
        "DH-3072",
        CryptoFamily.KEY_AGREEMENT,
        QuantumThreat.BROKEN,
        Standard.SP_800_56A,
        classical_bits=128,
        aliases=("FFDHE3072",),
        replaces_with=_PQ_KEM_GENERAL,
        disallowed_after=2035,
    ),
    # -- Symmetric (Grover-weakened, not broken) ---------------------------
    AlgorithmRecord(
        "AES-128",
        CryptoFamily.SYMMETRIC,
        QuantumThreat.WEAKENED,
        Standard.FIPS_197,
        nist_category=1,
        classical_bits=128,
        notes="Grover -> ~64-bit; NIST category 1.",
    ),
    AlgorithmRecord(
        "AES-192",
        CryptoFamily.SYMMETRIC,
        QuantumThreat.WEAKENED,
        Standard.FIPS_197,
        nist_category=3,
        classical_bits=192,
    ),
    AlgorithmRecord(
        "AES-256",
        CryptoFamily.SYMMETRIC,
        QuantumThreat.WEAKENED,
        Standard.FIPS_197,
        nist_category=5,
        classical_bits=256,
        cnsa_2_0=True,
        notes="CNSA 2.0 symmetric; Grover -> ~128-bit, ample.",
    ),
    AlgorithmRecord(
        "3DES",
        CryptoFamily.SYMMETRIC,
        QuantumThreat.WEAKENED,
        Standard.FIPS_197,
        classical_bits=112,
        disallowed_after=2023,
        notes="Classically deprecated (sweet32); migrate to AES-256.",
    ),
    # -- Hashes ------------------------------------------------------------
    AlgorithmRecord(
        "SHA-256",
        CryptoFamily.HASH,
        QuantumThreat.WEAKENED,
        Standard.FIPS_180_4,
        nist_category=2,
        classical_bits=256,
        aliases=("sha256",),
        notes="Grover -> ~128-bit preimage; quantum-acceptable.",
    ),
    AlgorithmRecord(
        "SHA-384",
        CryptoFamily.HASH,
        QuantumThreat.WEAKENED,
        Standard.FIPS_180_4,
        nist_category=3,
        classical_bits=384,
        aliases=("sha384",),
        cnsa_2_0=True,
    ),
    AlgorithmRecord(
        "SHA-512",
        CryptoFamily.HASH,
        QuantumThreat.WEAKENED,
        Standard.FIPS_180_4,
        nist_category=5,
        classical_bits=512,
        aliases=("sha512",),
        cnsa_2_0=True,
    ),
    AlgorithmRecord(
        "SHA3-256",
        CryptoFamily.HASH,
        QuantumThreat.WEAKENED,
        Standard.FIPS_202,
        nist_category=2,
        classical_bits=256,
        aliases=("sha3_256",),
    ),
    AlgorithmRecord(
        "SHAKE256",
        CryptoFamily.HASH,
        QuantumThreat.WEAKENED,
        Standard.FIPS_202,
        nist_category=5,
        classical_bits=256,
        aliases=("shake_256", "shake256"),
    ),
    AlgorithmRecord(
        "SHA-1",
        CryptoFamily.HASH,
        QuantumThreat.BROKEN,
        Standard.FIPS_180_4,
        classical_bits=80,
        aliases=("sha1",),
        disallowed_after=2030,
        notes="Classically broken (collisions); do not use.",
    ),
    AlgorithmRecord(
        "MD5",
        CryptoFamily.HASH,
        QuantumThreat.BROKEN,
        classical_bits=64,
        aliases=("md5",),
        disallowed_after=2010,
        notes="Classically broken.",
    ),
    # -- MAC ---------------------------------------------------------------
    AlgorithmRecord(
        "HMAC-SHA256",
        CryptoFamily.MAC,
        QuantumThreat.WEAKENED,
        Standard.FIPS_180_4,
        classical_bits=256,
        aliases=(
            "hmac-sha256",
            "hmac",
        ),
        notes="Symmetric MAC; Grover-only. Engine's always-on integrity baseline.",
    ),
)


def _build_index() -> dict[str, AlgorithmRecord]:
    index: dict[str, AlgorithmRecord] = {}
    for record in _RECORDS:
        index[record.name.casefold()] = record
        for alias in record.aliases:
            index.setdefault(alias.casefold(), record)
    return index


_INDEX: dict[str, AlgorithmRecord] = _build_index()


def all_algorithms() -> tuple[AlgorithmRecord, ...]:
    """Every registered algorithm record."""
    return _RECORDS


def get(name: str) -> AlgorithmRecord | None:
    """Look up an algorithm by canonical name or any alias (case-insensitive)."""
    return _INDEX.get(name.strip().casefold())


def require(name: str) -> AlgorithmRecord:
    record = get(name)
    if record is None:
        raise KeyError(f"unknown algorithm {name!r}")
    return record


def is_quantum_vulnerable(name: str) -> bool:
    """True only if the named algorithm is Shor-broken (BROKEN). Unknown -> False."""
    record = get(name)
    return record is not None and record.quantum_vulnerable


def recommended_replacements(name: str) -> tuple[str, ...]:
    """The recommended post-quantum replacement(s) for a vulnerable algorithm."""
    record = get(name)
    return record.replaces_with if record is not None else ()


def transition_year(name: str) -> int | None:
    """The year the algorithm becomes disallowed (NIST IR 8547), if any."""
    record = get(name)
    return record.disallowed_after if record is not None else None


def cnsa_2_0_suite() -> tuple[AlgorithmRecord, ...]:
    """The algorithms that make up the CNSA 2.0 suite."""
    return tuple(record for record in _RECORDS if record.cnsa_2_0)


def by_family(family: CryptoFamily) -> tuple[AlgorithmRecord, ...]:
    return tuple(record for record in _RECORDS if record.family is family)


def quantum_safe_signatures() -> tuple[AlgorithmRecord, ...]:
    """PQ signature algorithms, useful for picking a signing backend."""
    return tuple(
        record
        for record in _RECORDS
        if record.family is CryptoFamily.SIGNATURE and record.quantum_safe
    )
