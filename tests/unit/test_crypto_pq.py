from __future__ import annotations

import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from greynoc_detector_engine.cli.main import app
from greynoc_detector_engine.config.settings import get_settings
from greynoc_detector_engine.crypto import (
    HybridSigner,
    SignatureEnvelope,
    SigningKeyset,
    crypto_posture,
    ed25519_available,
    generate_keyset,
    keyset_from_hmac_secret,
    mldsa_available,
)
from greynoc_detector_engine.utils.hashing import (
    digest_bytes,
    is_quantum_resistant_hash,
    stable_hash,
)

PAYLOAD = b"GreyNOC Detector Engine detection bundle v1"


def test_hashing_is_algorithm_agile() -> None:
    assert stable_hash("x", algorithm="sha256") != stable_hash("x", algorithm="sha3_256")
    assert len(digest_bytes(b"x", algorithm="sha3_256")) == 64
    assert is_quantum_resistant_hash("sha256") is True
    assert is_quantum_resistant_hash("sha3_256") is True


def test_hashing_refuses_broken_primitives() -> None:
    with pytest.raises(ValueError, match="broken"):
        stable_hash("x", algorithm="md5")
    with pytest.raises(ValueError, match="broken"):
        stable_hash("x", algorithm="sha1")


def test_hmac_baseline_is_always_available_and_quantum_resistant() -> None:
    signer = HybridSigner(generate_keyset(hmac=True))
    envelope = signer.sign(PAYLOAD)
    assert envelope.algorithms == ["hmac-sha256"]
    assert envelope.quantum_resistant is True  # symmetric MAC survives Grover
    result = signer.verify(PAYLOAD, envelope)
    assert result.ok is True
    assert result.strongest_algorithm == "hmac-sha256"
    assert result.quantum_resistant is True


def test_tamper_is_detected() -> None:
    signer = HybridSigner(generate_keyset(hmac=True))
    envelope = signer.sign(PAYLOAD)
    result = signer.verify(PAYLOAD + b"!", envelope)
    assert result.ok is False
    assert result.verified["hmac-sha256"] is False


def test_wrong_key_does_not_verify() -> None:
    envelope = HybridSigner(generate_keyset(hmac=True)).sign(PAYLOAD)
    other = HybridSigner(SigningKeyset(hmac_key=os.urandom(32)))
    assert other.verify(PAYLOAD, envelope).ok is False


def test_missing_key_is_unverifiable_not_a_pass() -> None:
    envelope = HybridSigner(keyset_from_hmac_secret("shared-secret")).sign(PAYLOAD)
    no_key = HybridSigner(SigningKeyset())
    result = no_key.verify(PAYLOAD, envelope)
    assert result.ok is False
    assert "hmac-sha256" in result.unverifiable


def test_envelope_round_trips_through_json() -> None:
    envelope = HybridSigner(keyset_from_hmac_secret("k")).sign(PAYLOAD)
    restored = SignatureEnvelope.model_validate_json(envelope.model_dump_json())
    assert restored.payload_digest == envelope.payload_digest
    assert HybridSigner(keyset_from_hmac_secret("k")).verify(PAYLOAD, restored).ok is True


def test_signing_requires_at_least_one_backend() -> None:
    with pytest.raises(RuntimeError, match="no usable signing backend"):
        HybridSigner(SigningKeyset()).sign(PAYLOAD)


def test_posture_is_honest_about_backends() -> None:
    posture = crypto_posture()
    assert posture.hmac_signing is True
    assert posture.hash_quantum_resistant is True
    assert posture.mldsa_signing == mldsa_available()
    assert posture.ed25519_signing == ed25519_available()
    assert posture.findings
    # LMS/HSS is pure stdlib, so PQ non-repudiation -- and PQ readiness -- hold
    # out of the box, independent of the optional liboqs ML-DSA backend.
    assert posture.lms_signing is True
    assert posture.pq_non_repudiation is True
    assert posture.ready is True
    assert posture.ready == (posture.hash_quantum_resistant and posture.pq_non_repudiation)


@pytest.mark.skipif(not ed25519_available(), reason="cryptography (Ed25519) not installed")
def test_ed25519_asymmetric_path() -> None:
    signer = HybridSigner(generate_keyset(hmac=True, ed25519=True))
    envelope = signer.sign(PAYLOAD)
    assert "ed25519" in envelope.algorithms
    # The public key is embedded, so a verifier without the private keyset can check it.
    verifier = HybridSigner(SigningKeyset())
    result = verifier.verify(PAYLOAD, envelope)
    assert result.verified.get("ed25519") is True


@pytest.mark.skipif(
    not (ed25519_available() and mldsa_available()),
    reason="hybrid needs both cryptography and oqs",
)
def test_full_hybrid_signature() -> None:
    envelope = HybridSigner(generate_keyset(hmac=True, ed25519=True, mldsa=True)).sign(PAYLOAD)
    assert envelope.is_hybrid is True
    assert envelope.quantum_resistant is True


def test_lms_gives_post_quantum_non_repudiation_in_stdlib() -> None:
    # The headline: real PQ public-key non-repudiation with no optional backend.
    signer = HybridSigner(generate_keyset(hmac=True, lms=True))
    envelope = signer.sign(PAYLOAD)
    assert "hss-lms" in envelope.algorithms
    assert envelope.quantum_resistant is True
    # The LMS public key is embedded, so a verifier with NO private keyset can
    # still check the post-quantum signature.
    result = HybridSigner(SigningKeyset()).verify(PAYLOAD, envelope)
    assert result.verified.get("hss-lms") is True
    assert result.quantum_resistant is True
    assert result.strongest_algorithm == "hss-lms"


def test_lms_state_advances_so_each_signature_differs() -> None:
    keyset = generate_keyset(hmac=False, lms=True)
    signer = HybridSigner(keyset)
    first = signer.sign(PAYLOAD)
    second = signer.sign(PAYLOAD)
    # Stateful: the same payload signed twice consumes two one-time leaves and
    # yields two distinct, individually-valid signatures.
    assert first.components[0].signature != second.components[0].signature
    assert HybridSigner(SigningKeyset()).verify(PAYLOAD, first).ok is True
    assert HybridSigner(SigningKeyset()).verify(PAYLOAD, second).ok is True


def test_doctor_crypto_cli_runs() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["doctor", "crypto"])
    # The stdlib LMS backend makes the engine PQ-ready in every environment, so
    # the exit code is 0 even though optional-backend gaps remain (informational
    # "warn" findings). A non-zero exit is reserved for an actual readiness loss.
    assert result.exit_code == 0
    assert "crypto." in result.output


def test_verify_signature_cli_round_trip(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("GREYNOC_SIGNING_HMAC_KEY", "cli-shared-secret")
    get_settings.cache_clear()
    try:
        artifact = tmp_path / "bundle.json"
        artifact.write_bytes(PAYLOAD)
        envelope = HybridSigner(keyset_from_hmac_secret("cli-shared-secret")).sign(PAYLOAD)
        sig = tmp_path / "bundle.json.sig.json"
        sig.write_text(envelope.model_dump_json(), encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(app, ["verify-signature", str(artifact), str(sig)])
        assert result.exit_code == 0
        assert '"ok": true' in result.output

        artifact.write_bytes(PAYLOAD + b"tampered")
        tampered = runner.invoke(app, ["verify-signature", str(artifact), str(sig)])
        assert tampered.exit_code == 2
    finally:
        get_settings.cache_clear()
