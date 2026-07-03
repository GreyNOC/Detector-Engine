"""Hybrid (classical + post-quantum) key encapsulation and artifact encryption.

This mirrors the philosophy of :mod:`greynoc_detector_engine.crypto.signing`:
offline-first, dependency-light, and brutally honest about its posture. Where the
signer protects *integrity / non-repudiation*, this module protects
*confidentiality at rest* against the harvest-now-decrypt-later threat.

The scheme is a **hybrid KEM + AEAD**:

  * **Classical agreement (always, via ``cryptography``):** an ephemeral X25519
    key exchange against the recipient's long-term X25519 public key.
  * **Post-quantum encapsulation (optional):** ML-KEM-768 (NIST FIPS-203) via
    ``oqs`` (liboqs) if importable, else the pure-Python ``kyber_py`` backend.
  * Both shared secrets are concatenated and run through HKDF-SHA256 to derive a
    single 32-byte key, which keys **AES-256-GCM** over the payload. The public
    bundle / algorithm identifiers are bound in as AEAD associated data.

When an ML-KEM backend is present the envelope is a true hybrid and
``quantum_safe`` is ``True`` -- confidentiality holds as long as *either*
primitive holds. When ML-KEM is absent the scheme degrades to X25519-only and
``quantum_safe`` is ``False`` (clearly flagged in the posture and the envelope).
If ``cryptography`` itself is absent the module still imports, but
:func:`encrypt` / :func:`decrypt` raise a clear ``RuntimeError``.
"""

from __future__ import annotations

import base64
import importlib.util
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field

from greynoc_detector_engine.utils.time import utc_now

if TYPE_CHECKING:
    from collections.abc import Callable

ALG_X25519 = "x25519"
ALG_MLKEM = "ml-kem-768"
ALG_AEAD = "aes-256-gcm"
ALG_KDF = "hkdf-sha256"

_MLKEM_MECHANISM = "ML-KEM-768"  # liboqs mechanism name
_HKDF_INFO = b"greynoc-detector-engine/hybrid-kem/v1"
_DERIVED_KEY_BYTES = 32  # AES-256
_NONCE_BYTES = 12  # AES-GCM standard nonce


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def x25519_available() -> bool:
    """Whether the classical X25519 backend (``cryptography``) is importable."""
    return importlib.util.find_spec("cryptography") is not None


def mlkem_available() -> bool:
    """Whether a post-quantum ML-KEM backend (``oqs`` or ``kyber_py``) is importable."""
    return _mlkem_backend() is not None


def kem_available() -> bool:
    """Whether the minimum viable KEM (X25519 + AES-256-GCM) can run here."""
    return x25519_available()


def _mlkem_backend() -> str | None:
    """Return the name of the preferred ML-KEM backend, or ``None`` if absent.

    ``oqs`` (liboqs, C-backed) is preferred over the pure-Python ``kyber_py``.
    """
    if importlib.util.find_spec("oqs") is not None:
        return "oqs"
    if importlib.util.find_spec("kyber_py") is not None:
        return "kyber_py"
    return None


# --------------------------------------------------------------------------- #
# HKDF-SHA256 (prefer cryptography; fall back to a tiny stdlib implementation) #
# --------------------------------------------------------------------------- #


def _hkdf_sha256(ikm: bytes, *, info: bytes, length: int = _DERIVED_KEY_BYTES) -> bytes:
    """Derive ``length`` bytes from ``ikm`` via HKDF-SHA256 (RFC 5869).

    Uses ``cryptography``'s HKDF when available; otherwise a stdlib ``hmac``
    implementation. The salt is omitted (RFC 5869 permits an all-zero salt),
    which is safe here because the IKM is itself high-entropy shared-secret
    material, not a low-entropy password.
    """
    if x25519_available():
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF

        hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info)
        return hkdf.derive(ikm)
    return _hkdf_sha256_stdlib(ikm, info=info, length=length)


def _hkdf_sha256_stdlib(ikm: bytes, *, info: bytes, length: int) -> bytes:
    import hashlib
    import hmac

    hash_len = hashlib.sha256().digest_size
    if length > 255 * hash_len:
        raise ValueError("HKDF cannot derive more than 255*HashLen bytes")
    # Extract with an all-zero salt, then expand.
    prk = hmac.new(b"\x00" * hash_len, ikm, hashlib.sha256).digest()
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


# --------------------------------------------------------------------------- #
# Key material                                                                 #
# --------------------------------------------------------------------------- #


@dataclass
class HybridKemKeypair:
    """Recipient key material. Treat every private field as a secret.

    Holds the long-term X25519 keypair and, when an ML-KEM backend is active, a
    long-term ML-KEM keypair. :meth:`public_bundle` returns the JSON-safe public
    half a sender needs to encrypt to this recipient.
    """

    key_id: str = "dev"
    x25519_private_bytes: bytes | None = None  # 32-byte raw private key
    x25519_public_bytes: bytes | None = None  # 32-byte raw public key
    mlkem_secret_key: bytes | None = None
    mlkem_public_key: bytes | None = None
    mlkem_algorithm: str = _MLKEM_MECHANISM

    @property
    def has_mlkem(self) -> bool:
        return self.mlkem_secret_key is not None and self.mlkem_public_key is not None

    def public_bundle(self) -> dict[str, Any]:
        """Return the JSON-safe public bundle a sender encrypts against."""
        if self.x25519_public_bytes is None:
            raise RuntimeError("keypair has no X25519 public key")
        bundle: dict[str, Any] = {
            "schema_version": 1,
            "key_id": self.key_id,
            "algorithms": [ALG_X25519],
            "x25519_public": _b64e(self.x25519_public_bytes),
            "mlkem_public": None,
            "mlkem_algorithm": None,
        }
        if self.mlkem_public_key is not None:
            bundle["algorithms"] = [ALG_X25519, ALG_MLKEM]
            bundle["mlkem_public"] = _b64e(self.mlkem_public_key)
            bundle["mlkem_algorithm"] = self.mlkem_algorithm
        return bundle

    def to_dict(self) -> dict[str, Any]:
        """Serialize the FULL keypair, including private material (a secret)."""

        def _enc(raw: bytes | None) -> str | None:
            return _b64e(raw) if raw is not None else None

        return {
            "schema_version": 1,
            "key_id": self.key_id,
            "x25519_private": _enc(self.x25519_private_bytes),
            "x25519_public": _enc(self.x25519_public_bytes),
            "mlkem_secret": _enc(self.mlkem_secret_key),
            "mlkem_public": _enc(self.mlkem_public_key),
            "mlkem_algorithm": self.mlkem_algorithm,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> HybridKemKeypair:
        def _dec(key: str) -> bytes | None:
            value = data.get(key)
            return _b64d(value) if isinstance(value, str) else None

        return cls(
            key_id=str(data.get("key_id", "dev")),
            x25519_private_bytes=_dec("x25519_private"),
            x25519_public_bytes=_dec("x25519_public"),
            mlkem_secret_key=_dec("mlkem_secret"),
            mlkem_public_key=_dec("mlkem_public"),
            mlkem_algorithm=str(data.get("mlkem_algorithm", _MLKEM_MECHANISM)),
        )


def generate_kem_keypair(key_id: str = "dev") -> HybridKemKeypair:
    """Generate a fresh hybrid KEM keypair.

    Always generates an X25519 keypair (requires ``cryptography``). When an
    ML-KEM backend is importable, additionally generates an ML-KEM-768 keypair so
    encryption to this recipient is quantum-safe. Raises ``RuntimeError`` when no
    usable backend is present.
    """
    if not x25519_available():
        raise RuntimeError(
            "key encapsulation requires the 'cryptography' package, which is not installed"
        )
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    private = X25519PrivateKey.generate()
    keypair = HybridKemKeypair(
        key_id=key_id,
        x25519_private_bytes=private.private_bytes_raw(),
        x25519_public_bytes=private.public_key().public_bytes_raw(),
    )

    backend = _mlkem_backend()
    if backend is not None:
        public_key, secret_key = _mlkem_keygen(backend)
        keypair.mlkem_public_key = public_key
        keypair.mlkem_secret_key = secret_key
        keypair.mlkem_algorithm = _MLKEM_MECHANISM
    return keypair


# --------------------------------------------------------------------------- #
# ML-KEM backend shims (handle the two libraries' opposite tuple orders)       #
# --------------------------------------------------------------------------- #


def _mlkem_keygen(backend: str) -> tuple[bytes, bytes]:
    """Return ``(public_key, secret_key)`` for the active ML-KEM backend."""
    if backend == "oqs":
        import oqs

        with oqs.KeyEncapsulation(_MLKEM_MECHANISM) as kem:
            public_key = bytes(kem.generate_keypair())
            secret_key = bytes(kem.export_secret_key())
        return public_key, secret_key

    from kyber_py.ml_kem import ML_KEM_768

    encapsulation_key, decapsulation_key = ML_KEM_768.keygen()
    return bytes(encapsulation_key), bytes(decapsulation_key)


def _mlkem_encapsulate(backend: str, public_key: bytes) -> tuple[bytes, bytes]:
    """Return ``(ciphertext, shared_secret)`` for the active ML-KEM backend.

    liboqs yields ``(ciphertext, shared_secret)`` from ``encap_secret`` whereas
    ``kyber_py`` yields ``(shared_secret, ciphertext)`` from ``encaps`` -- the
    opposite order. Both are normalised to ciphertext-first here.
    """
    if backend == "oqs":
        import oqs

        with oqs.KeyEncapsulation(_MLKEM_MECHANISM) as kem:
            ciphertext, shared_secret = kem.encap_secret(public_key)
        return bytes(ciphertext), bytes(shared_secret)

    from kyber_py.ml_kem import ML_KEM_768

    shared_secret, ciphertext = ML_KEM_768.encaps(public_key)
    return bytes(ciphertext), bytes(shared_secret)


def _mlkem_decapsulate(backend: str, secret_key: bytes, ciphertext: bytes) -> bytes:
    """Return the shared secret recovered from ``ciphertext``."""
    if backend == "oqs":
        import oqs

        with oqs.KeyEncapsulation(_MLKEM_MECHANISM, secret_key) as kem:
            shared_secret = kem.decap_secret(ciphertext)
        return bytes(shared_secret)

    from kyber_py.ml_kem import ML_KEM_768

    shared_secret = ML_KEM_768.decaps(secret_key, ciphertext)
    return bytes(shared_secret)


# --------------------------------------------------------------------------- #
# Envelope + posture models                                                    #
# --------------------------------------------------------------------------- #


class KemEnvelope(BaseModel):
    """A self-describing, JSON-round-trippable encrypted artifact envelope."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = 1
    algorithms: list[str] = Field(default_factory=list)
    quantum_safe: bool = False
    x25519_ephemeral_public: str | None = None  # base64
    mlkem_ciphertext: str | None = None  # base64; present only on the hybrid path
    nonce: str  # base64; 12-byte AES-GCM nonce
    ciphertext: str  # base64; AES-256-GCM output (ciphertext || tag)
    created_at: datetime = Field(default_factory=utc_now)

    def associated_data(self) -> bytes:
        """Reconstruct the AEAD associated data bound at encryption time.

        Binds the algorithm identifiers, the quantum-safe flag, and the public
        ephemeral/ciphertext material so none of it can be swapped undetected.
        """
        parts = [
            f"v={self.schema_version}",
            "algs=" + ",".join(self.algorithms),
            f"qs={int(self.quantum_safe)}",
            "x25519=" + (self.x25519_ephemeral_public or ""),
            "mlkem=" + (self.mlkem_ciphertext or ""),
        ]
        return "|".join(parts).encode("utf-8")


class KemPosture(BaseModel):
    """Honest report of which KEM backends are active at runtime."""

    model_config = ConfigDict(extra="forbid")

    x25519: bool
    mlkem: bool
    aead: bool
    mlkem_backend: str | None
    quantum_safe: bool
    findings: list[str] = Field(default_factory=list)
    assessed_at: datetime = Field(default_factory=utc_now)


def kem_posture() -> KemPosture:
    """Report which KEM backends are active and whether encryption is quantum-safe."""
    x25519 = x25519_available()
    backend = _mlkem_backend()
    mlkem = backend is not None
    aead = x25519  # AES-GCM ships with cryptography, same gate as X25519
    quantum_safe = mlkem and aead

    findings: list[str] = []
    if not x25519:
        findings.append(
            "the 'cryptography' package is not installed; encryption/decryption are unavailable"
        )
    if x25519 and not mlkem:
        findings.append(
            "no ML-KEM backend ('oqs' or 'kyber_py'); encryption is classical X25519-only "
            "and NOT quantum-safe (vulnerable to harvest-now-decrypt-later)"
        )
    if quantum_safe:
        findings.append(
            f"hybrid X25519 + ML-KEM-768 active via '{backend}'; confidentiality is quantum-safe"
        )
    return KemPosture(
        x25519=x25519,
        mlkem=mlkem,
        aead=aead,
        mlkem_backend=backend,
        quantum_safe=quantum_safe,
        findings=findings,
    )


# --------------------------------------------------------------------------- #
# Encrypt / decrypt                                                            #
# --------------------------------------------------------------------------- #


def _require_aead() -> Callable[..., Any]:
    if not x25519_available():
        raise RuntimeError(
            "key encapsulation requires the 'cryptography' package, which is not installed"
        )
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    return AESGCM


def encrypt(payload: bytes, recipient_public_bundle: dict[str, Any]) -> KemEnvelope:
    """Encrypt ``payload`` for the holder of ``recipient_public_bundle``.

    The bundle is the dict produced by :meth:`HybridKemKeypair.public_bundle`.
    When it carries an ML-KEM public key *and* a local ML-KEM backend is
    available, the result is a quantum-safe hybrid envelope; otherwise it is a
    flagged X25519-only envelope.
    """
    aesgcm_cls = _require_aead()
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )

    recipient_x25519_b64 = recipient_public_bundle.get("x25519_public")
    if not isinstance(recipient_x25519_b64, str):
        raise ValueError("recipient bundle is missing a valid 'x25519_public' key")

    # Classical leg: ephemeral X25519 against the recipient's static public key.
    ephemeral = X25519PrivateKey.generate()
    recipient_public = X25519PublicKey.from_public_bytes(_b64d(recipient_x25519_b64))
    classical_secret = ephemeral.exchange(recipient_public)
    ephemeral_public_b64 = _b64e(ephemeral.public_key().public_bytes_raw())

    # Post-quantum leg (only when both the bundle and a local backend support it).
    algorithms = [ALG_X25519]
    mlkem_ciphertext_b64: str | None = None
    ikm = classical_secret
    backend = _mlkem_backend()
    recipient_mlkem_b64 = recipient_public_bundle.get("mlkem_public")
    if backend is not None and isinstance(recipient_mlkem_b64, str):
        ciphertext, pq_secret = _mlkem_encapsulate(backend, _b64d(recipient_mlkem_b64))
        mlkem_ciphertext_b64 = _b64e(ciphertext)
        ikm = classical_secret + pq_secret
        algorithms.append(ALG_MLKEM)

    quantum_safe = ALG_MLKEM in algorithms
    key = _hkdf_sha256(ikm, info=_HKDF_INFO)

    # Build the envelope shell first so its associated data matches exactly.
    import os

    nonce = os.urandom(_NONCE_BYTES)
    envelope = KemEnvelope(
        algorithms=algorithms,
        quantum_safe=quantum_safe,
        x25519_ephemeral_public=ephemeral_public_b64,
        mlkem_ciphertext=mlkem_ciphertext_b64,
        nonce=_b64e(nonce),
        ciphertext="",
    )
    aead = aesgcm_cls(key)
    sealed = aead.encrypt(nonce, payload, envelope.associated_data())
    envelope.ciphertext = _b64e(sealed)
    return envelope


def decrypt(envelope: KemEnvelope, keypair: HybridKemKeypair) -> bytes:
    """Decrypt ``envelope`` with the recipient's ``keypair``.

    Raises ``cryptography.exceptions.InvalidTag`` (an ``Exception`` subclass) on
    any tampering of the nonce, ciphertext, or bound associated data, and
    ``ValueError`` / ``RuntimeError`` on structural problems or a missing backend.
    """
    aesgcm_cls = _require_aead()
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )

    if keypair.x25519_private_bytes is None:
        raise RuntimeError("keypair has no X25519 private key; cannot decrypt")
    if envelope.x25519_ephemeral_public is None:
        raise ValueError("envelope has no X25519 ephemeral public key")

    private = X25519PrivateKey.from_private_bytes(keypair.x25519_private_bytes)
    ephemeral_public = X25519PublicKey.from_public_bytes(_b64d(envelope.x25519_ephemeral_public))
    classical_secret = private.exchange(ephemeral_public)
    ikm = classical_secret

    if ALG_MLKEM in envelope.algorithms:
        backend = _mlkem_backend()
        if backend is None:
            raise RuntimeError(
                "envelope is a hybrid ML-KEM envelope but no ML-KEM backend is installed"
            )
        if keypair.mlkem_secret_key is None:
            raise RuntimeError("keypair has no ML-KEM secret key; cannot decrypt hybrid envelope")
        if envelope.mlkem_ciphertext is None:
            raise ValueError("hybrid envelope is missing its ML-KEM ciphertext")
        pq_secret = _mlkem_decapsulate(
            backend, keypair.mlkem_secret_key, _b64d(envelope.mlkem_ciphertext)
        )
        ikm = classical_secret + pq_secret

    key = _hkdf_sha256(ikm, info=_HKDF_INFO)
    aead = aesgcm_cls(key)
    plaintext: bytes = aead.decrypt(
        _b64d(envelope.nonce), _b64d(envelope.ciphertext), envelope.associated_data()
    )
    return plaintext
