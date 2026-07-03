"""Hybrid (classical + post-quantum) detached signing of engine artifacts.

See the package docstring for the design rationale. The public surface is small:

    keyset = generate_keyset(hmac=True, ed25519=True, mldsa=True)
    signer = HybridSigner(keyset)
    envelope = signer.sign(bundle_bytes)        # -> SignatureEnvelope (JSON-able)
    result = signer.verify(bundle_bytes, envelope)
    assert result.ok and result.quantum_resistant

The asymmetric components embed their own public key, so a verifier needs only
the envelope and the artifact bytes -- not the private keyset -- to check
non-repudiation. The HMAC component requires the shared secret to verify.
"""

from __future__ import annotations

import base64
import hmac
import importlib.util
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field

from greynoc_detector_engine.crypto import hbs
from greynoc_detector_engine.utils.hashing import DEFAULT_HASH_ALGORITHM, digest_bytes
from greynoc_detector_engine.utils.time import utc_now

if TYPE_CHECKING:
    from collections.abc import Mapping

ALG_HMAC = "hmac-sha256"
ALG_ED25519 = "ed25519"
ALG_MLDSA = "ml-dsa-65"
ALG_LMS = "hss-lms"
_MLDSA_MECHANISM = "ML-DSA-65"

# Primitives that survive a cryptographically-relevant quantum computer.
# HMAC is symmetric (Grover-only); ML-DSA is a NIST PQC lattice signature; LMS/HSS
# is a NIST SP 800-208 hash-based signature (pure stdlib, always available).
# Ed25519 is classical -- broken by Shor -- and is present only for hybrid
# defence-in-depth during migration.
_QUANTUM_RESISTANT_ALGS: frozenset[str] = frozenset({ALG_HMAC, ALG_MLDSA, ALG_LMS})

# Public-key (asymmetric) signatures embed their own verification key in the
# envelope, so the signature alone only proves *internal consistency* -- any
# party can mint a fresh key and sign. Authenticity requires pinning the
# expected public key for these algorithms (see ``HybridSigner.verify``). HMAC is
# excluded: it is symmetric and already anchored to a shared secret in the keyset.
_ASYMMETRIC_ALGS: frozenset[str] = frozenset({ALG_ED25519, ALG_MLDSA, ALG_LMS})


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def _public_key_matches(embedded: str | None, expected: str) -> bool:
    """Whether an envelope component's public key equals the pinned ``expected`` one.

    Both are base64; comparison is over the decoded bytes so it is insensitive to
    padding or whitespace differences. A missing or malformed key never matches.
    These keys are public, so a constant-time compare is unnecessary.
    """
    if embedded is None:
        return False
    try:
        return _b64d(embedded) == _b64d(expected)
    except (ValueError, TypeError):
        return False


def ed25519_available() -> bool:
    """Whether the classical Ed25519 backend (``cryptography``) is importable."""
    return importlib.util.find_spec("cryptography") is not None


def mldsa_available() -> bool:
    """Whether the post-quantum ML-DSA backend (``oqs`` / liboqs) is importable."""
    return importlib.util.find_spec("oqs") is not None


def lms_available() -> bool:
    """Whether the post-quantum LMS/HSS signing backend is available.

    Always ``True``: LMS/HSS (RFC 8554 / NIST SP 800-208) is implemented in pure
    stdlib (:mod:`greynoc_detector_engine.crypto.hbs`), so the engine has
    post-quantum *non-repudiation* out of the box with no optional dependency and
    no liboqs build toolchain. The trade-off is that LMS is *stateful* -- each
    one-time key signs exactly once -- so its private state must be persisted
    after every signature (the keystore handles this).
    """
    return True


class SignatureComponent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    algorithm: str
    signature: str  # base64
    key_id: str
    quantum_resistant: bool
    public_key: str | None = None  # base64; present for asymmetric algorithms


class SignatureEnvelope(BaseModel):
    """A detached, multi-algorithm signature over an artifact's bytes."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = 1
    signer: str = "greynoc-detector-engine"
    hash_algorithm: str = DEFAULT_HASH_ALGORITHM
    payload_digest: str  # hex digest of the payload under hash_algorithm
    components: list[SignatureComponent] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)

    @property
    def algorithms(self) -> list[str]:
        return [component.algorithm for component in self.components]

    @property
    def is_hybrid(self) -> bool:
        """True when at least one classical and one PQ asymmetric signature coexist."""
        algs = set(self.algorithms)
        return ALG_ED25519 in algs and ALG_MLDSA in algs

    @property
    def quantum_resistant(self) -> bool:
        """True when at least one component survives a quantum adversary."""
        return any(component.quantum_resistant for component in self.components)


@dataclass
class SigningKeyset:
    """Private signing material. Treat every field as a secret."""

    key_id: str = "dev"
    hmac_key: bytes | None = None
    ed25519_private_bytes: bytes | None = None  # 32-byte raw seed
    ed25519_public_bytes: bytes | None = None  # 32-byte raw public key
    mldsa_secret_key: bytes | None = None
    mldsa_public_key: bytes | None = None
    mldsa_algorithm: str = _MLDSA_MECHANISM
    # Stateful post-quantum LMS/HSS private key (pure stdlib). Treat as a secret;
    # its state advances on every sign() and MUST be persisted afterwards.
    lms_private: hbs.HssPrivateKey | None = None


@dataclass
class VerificationResult:
    ok: bool
    verified: dict[str, bool]  # algorithm -> verified?
    unverifiable: dict[str, str]  # algorithm -> reason it could not be checked
    strongest_algorithm: str | None
    quantum_resistant: bool  # a quantum-resistant component verified
    notes: list[str] = field(default_factory=list)
    # algorithm -> whether its embedded public key matched a caller-supplied pin.
    # Empty when no pin was requested. ``any(pinned.values())`` answers "was at
    # least one verified component anchored to a trusted (pinned) key?" -- i.e.
    # is this an authenticated signature rather than a merely self-attesting one.
    pinned: dict[str, bool] = field(default_factory=dict)


def keyset_from_hmac_secret(secret: str, *, key_id: str = "config") -> SigningKeyset:
    """Build an HMAC-only keyset from a configured shared secret string."""
    if not secret:
        raise ValueError("signing secret must be a non-empty string")
    return SigningKeyset(key_id=key_id, hmac_key=secret.encode("utf-8"))


def generate_keyset(
    key_id: str = "dev",
    *,
    hmac: bool = True,
    ed25519: bool = False,
    mldsa: bool = False,
    lms: bool = False,
) -> SigningKeyset:
    """Generate fresh signing material for the requested backends.

    ``ed25519`` requires the ``cryptography`` package and ``mldsa`` requires
    ``oqs``; requesting an unavailable backend raises ``RuntimeError`` so a
    caller never believes it has a key it does not. ``lms`` (post-quantum
    hash-based signing) is always available -- it needs no optional dependency --
    but produces a *stateful* key: persist the keyset after each signature.
    """
    keyset = SigningKeyset(key_id=key_id)
    if hmac:
        keyset.hmac_key = os.urandom(32)
    if lms:
        # HSS L=2 over two height-5 trees: ~1024 signatures, fast lazy key gen.
        keyset.lms_private = hbs.generate_hss_key(
            levels=2,
            lms_type=hbs.LMS_SHA256_M32_H5,
            lmots_type=hbs.LMOTS_SHA256_N32_W8,
        )
    if ed25519:
        if not ed25519_available():
            raise RuntimeError("ed25519 requested but the 'cryptography' package is not installed")
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        private = Ed25519PrivateKey.generate()
        keyset.ed25519_private_bytes = private.private_bytes_raw()
        keyset.ed25519_public_bytes = private.public_key().public_bytes_raw()
    if mldsa:
        if not mldsa_available():
            raise RuntimeError("ml-dsa requested but the 'oqs' (liboqs) package is not installed")
        import oqs

        with oqs.Signature(_MLDSA_MECHANISM) as signer:
            keyset.mldsa_public_key = bytes(signer.generate_keypair())
            keyset.mldsa_secret_key = bytes(signer.export_secret_key())
        keyset.mldsa_algorithm = _MLDSA_MECHANISM
    return keyset


class HybridSigner:
    """Sign and verify artifact bytes with every backend the keyset supplies."""

    def __init__(self, keyset: SigningKeyset) -> None:
        self.keyset = keyset

    def active_algorithms(self) -> list[str]:
        algs: list[str] = []
        if self.keyset.hmac_key is not None:
            algs.append(ALG_HMAC)
        if self.keyset.ed25519_private_bytes is not None and ed25519_available():
            algs.append(ALG_ED25519)
        if self.keyset.mldsa_secret_key is not None and mldsa_available():
            algs.append(ALG_MLDSA)
        if self.keyset.lms_private is not None:
            algs.append(ALG_LMS)
        return algs

    def sign(
        self, payload: bytes, *, hash_algorithm: str = DEFAULT_HASH_ALGORITHM
    ) -> SignatureEnvelope:
        components: list[SignatureComponent] = []

        if self.keyset.hmac_key is not None:
            mac = hmac.new(self.keyset.hmac_key, payload, "sha256").digest()
            components.append(
                SignatureComponent(
                    algorithm=ALG_HMAC,
                    signature=_b64e(mac),
                    key_id=self.keyset.key_id,
                    quantum_resistant=True,
                )
            )

        if self.keyset.ed25519_private_bytes is not None and ed25519_available():
            components.append(self._sign_ed25519(payload))

        if self.keyset.mldsa_secret_key is not None and mldsa_available():
            components.append(self._sign_mldsa(payload))

        if self.keyset.lms_private is not None:
            components.append(self._sign_lms(payload))

        if not components:
            raise RuntimeError("keyset supplies no usable signing backend")

        return SignatureEnvelope(
            hash_algorithm=hash_algorithm,
            payload_digest=digest_bytes(payload, algorithm=hash_algorithm),
            components=components,
        )

    def _sign_ed25519(self, payload: bytes) -> SignatureComponent:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        assert self.keyset.ed25519_private_bytes is not None
        private = Ed25519PrivateKey.from_private_bytes(self.keyset.ed25519_private_bytes)
        signature: bytes = private.sign(payload)
        public_raw: bytes = private.public_key().public_bytes_raw()
        return SignatureComponent(
            algorithm=ALG_ED25519,
            signature=_b64e(signature),
            key_id=self.keyset.key_id,
            quantum_resistant=False,
            public_key=_b64e(public_raw),
        )

    def _sign_mldsa(self, payload: bytes) -> SignatureComponent:
        import oqs

        assert self.keyset.mldsa_secret_key is not None
        with oqs.Signature(self.keyset.mldsa_algorithm, self.keyset.mldsa_secret_key) as signer:
            signature = bytes(signer.sign(payload))
        assert self.keyset.mldsa_public_key is not None
        return SignatureComponent(
            algorithm=ALG_MLDSA,
            signature=_b64e(signature),
            key_id=self.keyset.key_id,
            quantum_resistant=True,
            public_key=_b64e(self.keyset.mldsa_public_key),
        )

    def _sign_lms(self, payload: bytes) -> SignatureComponent:
        # NOTE: this ADVANCES the stateful LMS/HSS key -- one one-time leaf is
        # consumed per call. The caller MUST persist self.keyset.lms_private
        # afterwards (the keystore does). The public key is embedded so a verifier
        # needs nothing but the envelope and the payload bytes.
        assert self.keyset.lms_private is not None
        signature = self.keyset.lms_private.sign(payload)
        public = self.keyset.lms_private.public_key().to_bytes()
        return SignatureComponent(
            algorithm=ALG_LMS,
            signature=_b64e(signature),
            key_id=self.keyset.key_id,
            quantum_resistant=True,
            public_key=_b64e(public),
        )

    def verify(
        self,
        payload: bytes,
        envelope: SignatureEnvelope,
        *,
        expected_public_keys: Mapping[str, str] | None = None,
    ) -> VerificationResult:
        """Verify ``envelope`` over ``payload``, optionally pinning public keys.

        ``expected_public_keys`` maps an asymmetric algorithm (``ed25519`` /
        ``ml-dsa-65`` / ``hss-lms``) to the base64 public key the verifier trusts.
        When a component's algorithm is pinned, its embedded public key MUST equal
        the pinned one or the component is **failed before any cryptographic
        check** (fail-closed) -- this is what turns a self-attesting signature
        into an authenticated one and stops the "mint a fresh key and re-sign"
        forgery. Unpinned components keep the previous self-attesting behaviour.
        """
        verified: dict[str, bool] = {}
        unverifiable: dict[str, str] = {}
        pinned: dict[str, bool] = {}
        pins = dict(expected_public_keys or {})

        for component in envelope.components:
            alg = component.algorithm
            if alg in pins and alg in _ASYMMETRIC_ALGS:
                matched = _public_key_matches(component.public_key, pins[alg])
                pinned[alg] = matched
                if not matched:
                    verified[alg] = False  # fail closed: untrusted signing key
                    continue
            if alg == ALG_HMAC:
                self._verify_hmac(payload, component, verified, unverifiable)
            elif alg == ALG_ED25519:
                self._verify_ed25519(payload, component, verified, unverifiable)
            elif alg == ALG_MLDSA:
                self._verify_mldsa(payload, component, verified, unverifiable)
            elif alg == ALG_LMS:
                self._verify_lms(payload, component, verified, unverifiable)
            else:
                unverifiable[alg] = "unknown algorithm"

        passed = {alg for alg, good in verified.items() if good}
        failed = {alg for alg, good in verified.items() if not good}
        pin_failures = {alg for alg, good in pinned.items() if not good}
        ok = bool(passed) and not failed
        strongest = self._strongest(passed)
        quantum = any(alg in _QUANTUM_RESISTANT_ALGS for alg in passed)
        notes: list[str] = []
        if pin_failures:
            notes.append(
                f"public key not trusted (pinned-key mismatch) for: {sorted(pin_failures)}"
            )
        if failed - pin_failures:
            notes.append(f"signature mismatch for: {sorted(failed - pin_failures)}")
        if unverifiable:
            notes.append(f"could not check (key/backend absent): {sorted(unverifiable)}")
        if ok and not quantum:
            notes.append("only classical signatures verified; not quantum-resistant")
        return VerificationResult(
            ok=ok,
            verified=verified,
            unverifiable=unverifiable,
            strongest_algorithm=strongest,
            quantum_resistant=quantum,
            notes=notes,
            pinned=pinned,
        )

    def _verify_hmac(
        self,
        payload: bytes,
        component: SignatureComponent,
        verified: dict[str, bool],
        unverifiable: dict[str, str],
    ) -> None:
        if self.keyset.hmac_key is None:
            unverifiable[ALG_HMAC] = "no shared HMAC key in keyset"
            return
        expected = hmac.new(self.keyset.hmac_key, payload, "sha256").digest()
        verified[ALG_HMAC] = hmac.compare_digest(expected, _b64d(component.signature))

    def _verify_ed25519(
        self,
        payload: bytes,
        component: SignatureComponent,
        verified: dict[str, bool],
        unverifiable: dict[str, str],
    ) -> None:
        if not ed25519_available():
            unverifiable[ALG_ED25519] = "cryptography backend not installed"
            return
        if component.public_key is None:
            unverifiable[ALG_ED25519] = "envelope component has no public key"
            return
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        public = Ed25519PublicKey.from_public_bytes(_b64d(component.public_key))
        try:
            public.verify(_b64d(component.signature), payload)
            verified[ALG_ED25519] = True
        except InvalidSignature:
            verified[ALG_ED25519] = False

    def _verify_mldsa(
        self,
        payload: bytes,
        component: SignatureComponent,
        verified: dict[str, bool],
        unverifiable: dict[str, str],
    ) -> None:
        if not mldsa_available():
            unverifiable[ALG_MLDSA] = "oqs (liboqs) backend not installed"
            return
        if component.public_key is None:
            unverifiable[ALG_MLDSA] = "envelope component has no public key"
            return
        import oqs

        with oqs.Signature(self.keyset.mldsa_algorithm) as verifier:
            ok = bool(
                verifier.verify(payload, _b64d(component.signature), _b64d(component.public_key))
            )
        verified[ALG_MLDSA] = ok

    def _verify_lms(
        self,
        payload: bytes,
        component: SignatureComponent,
        verified: dict[str, bool],
        unverifiable: dict[str, str],
    ) -> None:
        # LMS/HSS verification is pure stdlib -- no backend gate, always possible.
        if component.public_key is None:
            unverifiable[ALG_LMS] = "envelope component has no public key"
            return
        verified[ALG_LMS] = hbs.hss_verify(
            _b64d(component.public_key), payload, _b64d(component.signature)
        )

    @staticmethod
    def _strongest(passed: set[str]) -> str | None:
        # Preference: PQ lattice > PQ hash-based > classical asymmetric > symmetric MAC.
        for alg in (ALG_MLDSA, ALG_LMS, ALG_ED25519, ALG_HMAC):
            if alg in passed:
                return alg
        return None
