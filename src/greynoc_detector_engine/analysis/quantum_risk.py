"""Classify a threat's exposure to the quantum transition.

This is glass-box, keyword-driven classification in the same spirit as
``normalize/ai_attack_classifier.py``: a curated, auditable lexicon, no model
at request time. It answers three questions about a piece of threat text:

  1. Does it concern a **quantum-vulnerable primitive** (RSA, ECC, Diffie-Hellman,
     and the protocols/libraries built on them -- TLS, SSH, IPsec, PKI, ...)?
  2. Is it a **harvest-now-decrypt-later** (HNDL) risk -- i.e. a *confidentiality*
     primitive whose traffic an adversary can record today and decrypt once a
     cryptographically-relevant quantum computer (CRQC) exists?
  3. Is it **CNSA-2.0 / NIST-PQC migration relevant**?

Signatures (ECDSA, RSA code-signing) are treated as *moderate* rather than HNDL:
forging them needs a CRQC at attack time, not retroactively, so recorded traffic
is not the threat. Confidentiality primitives (RSA key transport, (EC)DH key
exchange, the TLS handshake) are *high*, and become *critical* when the text also
talks about harvesting / Q-Day explicitly.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from greynoc_detector_engine.models.quantum import QuantumRiskAssessment, QuantumRiskLevel


@dataclass(frozen=True)
class _Primitive:
    name: str
    patterns: tuple[str, ...]
    confidentiality: bool = False  # True == key exchange / encryption (HNDL-relevant)


# Quantum-vulnerable primitives and the protocols/libraries that depend on them.
# Patterns are matched case-insensitively with word boundaries so short tokens
# (rsa, dh, dsa) do not match inside unrelated words (parsa, dhcp, ...).
_PRIMITIVES: tuple[_Primitive, ...] = (
    _Primitive("RSA", ("rsa", "rsa-2048", "rsa-4096", "pkcs#1", "pkcs1"), confidentiality=True),
    _Primitive(
        "Diffie-Hellman",
        ("diffie-hellman", "diffie hellman", r"\bdh\b", "dhe", "finite field"),
        confidentiality=True,
    ),
    _Primitive("ECDH", ("ecdh", "ecdhe", "x25519", "curve25519", "x448"), confidentiality=True),
    _Primitive(
        "Key establishment",
        ("key exchange", "key agreement", "key encapsulation", "key transport"),
        confidentiality=True,
    ),
    _Primitive("ECC", ("ecc", "elliptic curve", "secp256r1", "secp384r1", "p-256", "p-384")),
    _Primitive("ECDSA", ("ecdsa", "ed25519", "ed448")),
    # Negative lookbehind so ML-DSA / SLH-DSA (the PQC *solutions*) and ECDSA do
    # not register as the vulnerable DSA primitive.
    _Primitive("DSA", (r"(?<![\w-])dsa\b",)),
    _Primitive("ElGamal", ("elgamal", "el gamal")),
    _Primitive(
        "TLS/SSL",
        ("tls", "ssl", "https", "openssl", "boringssl", "libressl", "gnutls", "mbedtls", "wolfssl"),
        confidentiality=True,
    ),
    _Primitive("SSH", ("ssh", "openssh"), confidentiality=True),
    _Primitive("IPsec/VPN", ("ipsec", "ike", "ikev2", "vpn"), confidentiality=True),
    _Primitive(
        "PKI/X.509",
        ("x.509", "x509", "certificate authority", "public key infrastructure"),
    ),
    _Primitive("PGP/S-MIME", ("pgp", "gpg", "openpgp", "s/mime"), confidentiality=True),
    _Primitive("JWT/JOSE", ("jwt", "jws", "rs256", "es256")),
    _Primitive("Code signing", ("code signing", "code-signing", "authenticode")),
)

# Explicit harvest-now-decrypt-later language.
_HNDL_TERMS: tuple[str, ...] = (
    "harvest now decrypt later",
    "harvest-now-decrypt-later",
    "harvest now, decrypt later",
    "store now decrypt later",
    "store-now-decrypt-later",
    "record now decrypt later",
    "retrospective decryption",
    "retroactive decryption",
    "hndl",
)

# A cryptographically-relevant quantum computer / Q-Day context escalates HNDL.
_CRQC_TERMS: tuple[str, ...] = (
    "cryptographically relevant quantum computer",
    "cryptographically-relevant quantum computer",
    "crqc",
    "q-day",
    "q day",
    "shor's algorithm",
    "shor algorithm",
)

# Quantum / PQC awareness and migration-standard terms.
_QUANTUM_TERMS: tuple[str, ...] = (
    "post-quantum",
    "post quantum",
    "quantum-safe",
    "quantum safe",
    "quantum-resistant",
    "quantum resistant",
    "quantum computer",
    "pqc",
)
_MIGRATION_TERMS: tuple[str, ...] = (
    "cnsa 2.0",
    "cnsa2.0",
    "fips 203",
    "fips 204",
    "fips 205",
    "ml-kem",
    "ml-dsa",
    "slh-dsa",
    "kyber",
    "dilithium",
    "sphincs",
    "nist pqc",
)


def _compile(terms: tuple[str, ...]) -> list[re.Pattern[str]]:
    compiled: list[re.Pattern[str]] = []
    for term in terms:
        # Terms already containing a regex anchor are used verbatim; plain terms
        # are escaped and wrapped in word boundaries so a short token like "rsa"
        # cannot match inside an unrelated word ("trave-rsa-l").
        pattern = term if ("\\b" in term or "(?<" in term) else r"\b" + re.escape(term) + r"\b"
        compiled.append(re.compile(pattern, re.IGNORECASE))
    return compiled


_HNDL_RE = _compile(_HNDL_TERMS)
_CRQC_RE = _compile(_CRQC_TERMS)
_QUANTUM_RE = _compile(_QUANTUM_TERMS)
_MIGRATION_RE = _compile(_MIGRATION_TERMS)
_PRIMITIVE_RE: list[tuple[_Primitive, list[re.Pattern[str]]]] = [
    (primitive, _compile(primitive.patterns)) for primitive in _PRIMITIVES
]


def _any(text: str, patterns: list[re.Pattern[str]]) -> list[str]:
    hits: list[str] = []
    for pattern in patterns:
        match = pattern.search(text)
        if match:
            hits.append(match.group(0).lower())
    return hits


class QuantumRiskClassifier:
    """Assess a threat's post-quantum exposure from its text and product list."""

    def assess(self, text: str, products: list[str] | None = None) -> QuantumRiskAssessment:
        haystack = " ".join([text or "", " ".join(products or [])]).strip()
        if not haystack:
            return QuantumRiskAssessment(
                risk_level=QuantumRiskLevel.NONE,
                score=0.0,
                quantum_vulnerable=False,
                harvest_now_decrypt_later=False,
                cnsa_2_0_relevant=False,
                rationale=["No text to assess."],
            )

        affected: list[str] = []
        confidentiality_exposed = False
        matched: list[str] = []
        for primitive, patterns in _PRIMITIVE_RE:
            hits = _any(haystack, patterns)
            if hits:
                affected.append(primitive.name)
                matched.extend(hits)
                confidentiality_exposed = confidentiality_exposed or primitive.confidentiality

        hndl_hits = _any(haystack, _HNDL_RE)
        crqc_hits = _any(haystack, _CRQC_RE)
        quantum_hits = _any(haystack, _QUANTUM_RE)
        migration_hits = _any(haystack, _MIGRATION_RE)
        matched.extend(hndl_hits + crqc_hits + quantum_hits + migration_hits)

        quantum_vulnerable = bool(affected)
        harvest_now_decrypt_later = bool(hndl_hits) or confidentiality_exposed
        cnsa_relevant = bool(migration_hits) or bool(quantum_hits) or quantum_vulnerable

        rationale: list[str] = []
        if affected:
            rationale.append(f"Quantum-vulnerable primitives referenced: {sorted(set(affected))}.")
        if hndl_hits:
            rationale.append("Text explicitly discusses harvest-now-decrypt-later.")
        elif confidentiality_exposed:
            rationale.append(
                "Confidentiality primitive exposed: recorded traffic is decryptable once a "
                "CRQC exists (harvest-now-decrypt-later)."
            )
        if crqc_hits:
            rationale.append("References a cryptographically-relevant quantum computer / Q-Day.")
        if migration_hits:
            rationale.append("Mentions a NIST PQC / CNSA-2.0 migration standard.")
        if quantum_hits and not affected:
            rationale.append("Post-quantum discussion without a concrete vulnerable primitive.")
        if not rationale:
            rationale.append("No quantum-relevant signals found.")

        level, score = self._grade(
            quantum_vulnerable=quantum_vulnerable,
            confidentiality_exposed=confidentiality_exposed,
            harvest_terms=bool(hndl_hits),
            crqc=bool(crqc_hits),
            quantum_awareness=bool(quantum_hits or migration_hits),
        )

        return QuantumRiskAssessment(
            risk_level=level,
            score=round(score, 4),
            quantum_vulnerable=quantum_vulnerable,
            harvest_now_decrypt_later=harvest_now_decrypt_later,
            cnsa_2_0_relevant=cnsa_relevant,
            affected_primitives=sorted(set(affected)),
            matched_terms=sorted(set(matched)),
            rationale=rationale,
        )

    @staticmethod
    def _grade(
        *,
        quantum_vulnerable: bool,
        confidentiality_exposed: bool,
        harvest_terms: bool,
        crqc: bool,
        quantum_awareness: bool,
    ) -> tuple[QuantumRiskLevel, float]:
        if not quantum_vulnerable:
            if quantum_awareness:
                return QuantumRiskLevel.LOW, 0.25
            return QuantumRiskLevel.NONE, 0.0
        if confidentiality_exposed:
            if harvest_terms or crqc:
                return QuantumRiskLevel.CRITICAL, 0.95
            return QuantumRiskLevel.HIGH, 0.75
        # Vulnerable but signature-only (forgery needs a CRQC at attack time).
        return QuantumRiskLevel.MODERATE, 0.5
