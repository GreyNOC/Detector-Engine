from __future__ import annotations

import base64

import pytest

try:
    from cryptography.exceptions import InvalidTag
except ImportError:

    class InvalidTag(Exception):
        pass


from greynoc_detector_engine.crypto.kem import (
    ALG_MLKEM,
    ALG_X25519,
    HybridKemKeypair,
    KemEnvelope,
    decrypt,
    encrypt,
    generate_kem_keypair,
    kem_available,
    kem_posture,
    mlkem_available,
    x25519_available,
)

PAYLOAD = b"GreyNOC Detector Engine confidential detection bundle v1"

pytestmark = pytest.mark.skipif(
    not kem_available(),
    reason="cryptography (X25519 + AES-256-GCM) not installed",
)


def test_round_trip_recovers_the_payload() -> None:
    keypair = generate_kem_keypair()
    envelope = encrypt(PAYLOAD, keypair.public_bundle())
    assert decrypt(envelope, keypair) == PAYLOAD


def test_envelope_advertises_x25519_and_aead() -> None:
    keypair = generate_kem_keypair()
    envelope = encrypt(PAYLOAD, keypair.public_bundle())
    assert ALG_X25519 in envelope.algorithms
    assert envelope.x25519_ephemeral_public is not None
    assert envelope.nonce
    assert envelope.ciphertext


def test_quantum_safe_flag_tracks_the_backend() -> None:
    keypair = generate_kem_keypair()
    envelope = encrypt(PAYLOAD, keypair.public_bundle())
    # quantum_safe is True iff the ML-KEM leg was actually used.
    assert envelope.quantum_safe == (ALG_MLKEM in envelope.algorithms)
    assert envelope.quantum_safe == mlkem_available()


@pytest.mark.skipif(mlkem_available(), reason="ML-KEM backend present; fallback path not exercised")
def test_fallback_is_flagged_not_quantum_safe() -> None:
    keypair = generate_kem_keypair()
    bundle = keypair.public_bundle()
    assert bundle["mlkem_public"] is None
    envelope = encrypt(PAYLOAD, bundle)
    assert envelope.quantum_safe is False
    assert ALG_MLKEM not in envelope.algorithms
    assert envelope.mlkem_ciphertext is None


def test_tampered_ciphertext_raises() -> None:
    keypair = generate_kem_keypair()
    envelope = encrypt(PAYLOAD, keypair.public_bundle())
    raw = bytearray(base64.b64decode(envelope.ciphertext))
    raw[0] ^= 0xFF
    envelope.ciphertext = base64.b64encode(bytes(raw)).decode("ascii")
    with pytest.raises(InvalidTag):
        decrypt(envelope, keypair)


def test_tampered_nonce_raises() -> None:
    keypair = generate_kem_keypair()
    envelope = encrypt(PAYLOAD, keypair.public_bundle())
    raw = bytearray(base64.b64decode(envelope.nonce))
    raw[0] ^= 0xFF
    envelope.nonce = base64.b64encode(bytes(raw)).decode("ascii")
    with pytest.raises(InvalidTag):
        decrypt(envelope, keypair)


def test_tampered_associated_data_raises() -> None:
    keypair = generate_kem_keypair()
    envelope = encrypt(PAYLOAD, keypair.public_bundle())
    # Flipping the quantum_safe flag changes the bound associated data.
    envelope.quantum_safe = not envelope.quantum_safe
    with pytest.raises(InvalidTag):
        decrypt(envelope, keypair)


def test_wrong_keypair_cannot_decrypt() -> None:
    keypair = generate_kem_keypair()
    other = generate_kem_keypair()
    envelope = encrypt(PAYLOAD, keypair.public_bundle())
    with pytest.raises(InvalidTag):
        decrypt(envelope, other)


def test_envelope_json_round_trips_and_still_decrypts() -> None:
    keypair = generate_kem_keypair()
    envelope = encrypt(PAYLOAD, keypair.public_bundle())
    restored = KemEnvelope.model_validate_json(envelope.model_dump_json())
    assert restored.algorithms == envelope.algorithms
    assert restored.quantum_safe == envelope.quantum_safe
    assert decrypt(restored, keypair) == PAYLOAD


def test_public_bundle_is_json_safe() -> None:
    keypair = generate_kem_keypair()
    bundle = keypair.public_bundle()
    assert isinstance(bundle["x25519_public"], str)
    assert bundle["algorithms"][0] == ALG_X25519
    assert set(bundle) == {
        "schema_version",
        "key_id",
        "algorithms",
        "x25519_public",
        "mlkem_public",
        "mlkem_algorithm",
    }


def test_encrypt_rejects_bundle_without_x25519() -> None:
    with pytest.raises(ValueError, match="x25519_public"):
        encrypt(PAYLOAD, {"algorithms": []})


def test_decrypt_rejects_keypair_without_private_key() -> None:
    keypair = generate_kem_keypair()
    envelope = encrypt(PAYLOAD, keypair.public_bundle())
    blind = HybridKemKeypair(x25519_public_bytes=keypair.x25519_public_bytes)
    with pytest.raises(RuntimeError, match="no X25519 private key"):
        decrypt(envelope, blind)


def test_posture_is_honest_about_backends() -> None:
    posture = kem_posture()
    assert posture.x25519 is x25519_available()
    assert posture.mlkem is mlkem_available()
    assert posture.aead is x25519_available()
    assert posture.quantum_safe == (posture.mlkem and posture.aead)
    assert posture.findings
    if not posture.mlkem:
        assert any("quantum-safe" in finding.lower() for finding in posture.findings)


def test_distinct_envelopes_use_fresh_nonces() -> None:
    keypair = generate_kem_keypair()
    first = encrypt(PAYLOAD, keypair.public_bundle())
    second = encrypt(PAYLOAD, keypair.public_bundle())
    assert first.nonce != second.nonce
    assert first.x25519_ephemeral_public != second.x25519_ephemeral_public
