"""Power-on self-test / known-answer tests for the crypto backends.

A small, dependency-free harness that exercises every crypto primitive the
engine can actually run in the current environment and reports, honestly,
whether each one is healthy. It is surfaced operationally by ``gn crypto
selftest`` and folded into the doctor so an operator can confirm at start-up
that the post-quantum signing, hashing, and KEM paths are sound before trusting
any signed or encrypted artifact.

Each individual check returns one of three statuses:

* ``"pass"`` -- the primitive ran and produced the expected (or
  tamper-rejecting) result.
* ``"fail"`` -- the primitive is present but misbehaved. This is the only
  status that drives :attr:`SelfTestReport.ok` to ``False``.
* ``"skip"`` -- an optional backend (e.g. ML-DSA via liboqs) is not installed,
  so the check was not applicable here. Skips never fail the report.

:func:`run_crypto_selftest` never raises: any unexpected exception inside a
check is caught and recorded as a ``"fail"`` with its detail, so the harness is
safe to call from a CLI or health endpoint.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from greynoc_detector_engine.crypto import hbs, kem, signing
from greynoc_detector_engine.utils.hashing import (
    digest_bytes,
    is_quantum_resistant_hash,
)

SelfTestStatus = Literal["pass", "fail", "skip"]

_PROBE = b"GreyNOC crypto self-test probe payload"


class SelfTestResult(BaseModel):
    """The outcome of a single crypto known-answer / round-trip check."""

    model_config = ConfigDict(extra="forbid")

    name: str
    status: SelfTestStatus
    detail: str = ""


class SelfTestReport(BaseModel):
    """Aggregate result of every crypto self-test run in this environment."""

    model_config = ConfigDict(extra="forbid")

    results: list[SelfTestResult] = Field(default_factory=list)
    passed: int = 0
    failed: int = 0
    skipped: int = 0

    @property
    def ok(self) -> bool:
        """True when no check failed (skips and passes are both acceptable)."""
        return self.failed == 0

    def as_dict(self) -> dict[str, object]:
        """JSON-safe summary, mirroring the eval harness's ``as_dict`` shape."""
        payload = self.model_dump(mode="json")
        payload["ok"] = self.ok
        return payload


def _pass(name: str, detail: str = "") -> SelfTestResult:
    return SelfTestResult(name=name, status="pass", detail=detail)


def _fail(name: str, detail: str) -> SelfTestResult:
    return SelfTestResult(name=name, status="fail", detail=detail)


def _skip(name: str, detail: str) -> SelfTestResult:
    return SelfTestResult(name=name, status="skip", detail=detail)


def _guard(name: str, check: Callable[[], SelfTestResult]) -> SelfTestResult:
    """Run ``check``; convert any escaping exception into a ``fail`` result."""
    try:
        return check()
    except Exception as exc:  # a self-test must never propagate an exception
        return _fail(name, f"unexpected error: {type(exc).__name__}: {exc}")


# --------------------------------------------------------------------------- #
# Individual checks                                                            #
# --------------------------------------------------------------------------- #


def _check_hash_agility() -> SelfTestResult:
    name = "hash.agility"
    sha256_a = digest_bytes(_PROBE, algorithm="sha256")
    sha256_b = digest_bytes(_PROBE, algorithm="sha256")
    if sha256_a != sha256_b:
        return _fail(name, "sha256 digest is not deterministic")
    sha3 = digest_bytes(_PROBE, algorithm="sha3_256")
    if sha256_a == sha3:
        return _fail(name, "sha256 and sha3_256 produced identical digests")
    if not is_quantum_resistant_hash("sha256"):
        return _fail(name, "sha256 was not reported as quantum-resistant")
    try:
        digest_bytes(_PROBE, algorithm="md5")
    except ValueError:
        return _pass(
            name,
            "sha256 deterministic, distinct from sha3_256, PQ-resistant; md5 refused",
        )
    return _fail(name, "broken hash md5 was NOT refused")


def _check_hmac() -> SelfTestResult:
    name = "signing.hmac"
    signer = signing.HybridSigner(signing.generate_keyset(hmac=True))
    envelope = signer.sign(_PROBE)
    if signing.ALG_HMAC not in envelope.algorithms:
        return _fail(name, "HMAC component missing from the signature envelope")
    result = signer.verify(_PROBE, envelope)
    if not result.ok:
        return _fail(name, f"HMAC verify failed: {result.notes}")
    tampered = signer.verify(_PROBE + b"!", envelope)
    if tampered.ok:
        return _fail(name, "HMAC verified a tampered payload")
    return _pass(name, "HMAC-SHA256 sign/verify roundtrip + tamper-detect OK")


def _check_lms_signing() -> SelfTestResult:
    name = "signing.lms"
    signer = signing.HybridSigner(signing.generate_keyset(hmac=False, lms=True))
    envelope = signer.sign(_PROBE)
    if signing.ALG_LMS not in envelope.algorithms:
        return _fail(name, "LMS/HSS component missing from the signature envelope")
    if not envelope.quantum_resistant:
        return _fail(name, "LMS envelope was not flagged quantum-resistant")
    # The LMS public key is embedded, so a keyless verifier must still validate.
    keyless = signing.HybridSigner(signing.SigningKeyset())
    result = keyless.verify(_PROBE, envelope)
    if not result.verified.get(signing.ALG_LMS):
        return _fail(name, f"keyless LMS verify failed: {result.notes}")
    if not result.quantum_resistant:
        return _fail(name, "keyless LMS verify did not report quantum resistance")
    tampered = keyless.verify(_PROBE + b"!", envelope)
    if tampered.ok:
        return _fail(name, "LMS verified a tampered payload")
    return _pass(
        name,
        "LMS/HSS sign + embedded-public-key keyless verify + tamper-detect OK",
    )


def _check_lms_rfc8554() -> SelfTestResult:
    name = "signing.lms.rfc8554"
    key = hbs.generate_hss_key(
        levels=2,
        lms_type=hbs.LMS_SHA256_M32_H5,
        lmots_type=hbs.LMOTS_SHA256_N32_W8,
    )
    public = key.public_key().to_bytes()
    signature = key.sign(_PROBE)
    if not hbs.hss_verify(public, _PROBE, signature):
        return _fail(name, "HSS signature did not verify against its own public key")
    flipped = bytes([signature[0] ^ 0x01]) + signature[1:]
    if hbs.hss_verify(public, _PROBE, flipped):
        return _fail(name, "HSS verified a signature with a flipped byte")
    if hbs.hss_verify(public, _PROBE + b"!", signature):
        return _fail(name, "HSS verified against a tampered message")
    return _pass(
        name,
        "RFC 8554 HSS self-consistency: verify OK, flipped-byte + tampered-message rejected",
    )


def _check_ed25519() -> SelfTestResult:
    name = "signing.ed25519"
    if not signing.ed25519_available():
        return _skip(name, "ed25519 backend ('cryptography') not installed")
    signer = signing.HybridSigner(signing.generate_keyset(hmac=False, ed25519=True))
    envelope = signer.sign(_PROBE)
    if signing.ALG_ED25519 not in envelope.algorithms:
        return _fail(name, "Ed25519 component missing from the signature envelope")
    # Embedded public key -> a keyless verifier can check the classical signature.
    keyless = signing.HybridSigner(signing.SigningKeyset())
    result = keyless.verify(_PROBE, envelope)
    if not result.verified.get(signing.ALG_ED25519):
        return _fail(name, f"keyless Ed25519 verify failed: {result.notes}")
    tampered = keyless.verify(_PROBE + b"!", envelope)
    if tampered.ok:
        return _fail(name, "Ed25519 verified a tampered payload")
    return _pass(name, "Ed25519 sign/verify roundtrip + tamper-detect OK (classical)")


def _check_mldsa() -> SelfTestResult:
    name = "signing.mldsa"
    if not signing.mldsa_available():
        return _skip(name, "ML-DSA backend ('oqs' / liboqs) not installed")
    signer = signing.HybridSigner(signing.generate_keyset(hmac=False, mldsa=True))
    envelope = signer.sign(_PROBE)
    if signing.ALG_MLDSA not in envelope.algorithms:
        return _fail(name, "ML-DSA component missing from the signature envelope")
    keyless = signing.HybridSigner(signing.SigningKeyset())
    result = keyless.verify(_PROBE, envelope)
    if not result.verified.get(signing.ALG_MLDSA):
        return _fail(name, f"keyless ML-DSA verify failed: {result.notes}")
    tampered = keyless.verify(_PROBE + b"!", envelope)
    if tampered.ok:
        return _fail(name, "ML-DSA verified a tampered payload")
    return _pass(name, "ML-DSA-65 sign/verify roundtrip + tamper-detect OK (PQ lattice)")


def _check_kem() -> SelfTestResult:
    name = "kem.roundtrip"
    if not kem.kem_available():
        return _skip(name, "KEM backend ('cryptography' X25519 + AES-GCM) not installed")
    keypair = kem.generate_kem_keypair("selftest")
    envelope = kem.encrypt(_PROBE, keypair.public_bundle())
    recovered = kem.decrypt(envelope, keypair)
    if recovered != _PROBE:
        return _fail(name, "decrypted payload did not match the original")
    safety = (
        "quantum-safe (hybrid ML-KEM)"
        if envelope.quantum_safe
        else "classical X25519-only (NOT quantum-safe)"
    )
    return _pass(name, f"KEM encrypt/decrypt roundtrip OK; confidentiality is {safety}")


_CHECKS: tuple[Callable[[], SelfTestResult], ...] = (
    _check_hash_agility,
    _check_hmac,
    _check_lms_signing,
    _check_lms_rfc8554,
    _check_ed25519,
    _check_mldsa,
    _check_kem,
)


def run_crypto_selftest() -> SelfTestReport:
    """Run every crypto known-answer / round-trip check in this environment.

    Never raises: a check that errors unexpectedly is recorded as a ``fail``
    rather than propagating. The returned report's :attr:`SelfTestReport.ok`
    is ``True`` exactly when no check failed.
    """
    results: list[SelfTestResult] = []
    for check in _CHECKS:
        result = _guard(check.__name__, check)
        results.append(result)

    passed = sum(1 for r in results if r.status == "pass")
    failed = sum(1 for r in results if r.status == "fail")
    skipped = sum(1 for r in results if r.status == "skip")
    return SelfTestReport(
        results=results,
        passed=passed,
        failed=failed,
        skipped=skipped,
    )
