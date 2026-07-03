"""Public-key pinning on signature verification.

An asymmetric signature embeds its own verification key, so the signature alone
only proves *internal consistency*: any party can mint a fresh key, re-sign a
tampered payload, and the result self-verifies. Pinning the expected public key
is what upgrades "internally consistent" to "authentic". These tests lock in the
fail-closed behaviour and that the unpinned path is unchanged.
"""

from __future__ import annotations

from greynoc_detector_engine.crypto import (
    ALG_LMS,
    HybridSigner,
    SignatureEnvelope,
    SigningKeyset,
    generate_keyset,
)

PAYLOAD = b"GreyNOC Detector Engine detection bundle v1"


def _lms_pub(envelope: SignatureEnvelope) -> str:
    """Extract the base64 LMS public key carried by an envelope."""
    for component in envelope.components:
        if component.algorithm == ALG_LMS:
            assert component.public_key is not None
            return component.public_key
    raise AssertionError("no LMS component in envelope")


def test_pinning_the_correct_key_verifies() -> None:
    envelope = HybridSigner(generate_keyset(hmac=False, lms=True)).sign(PAYLOAD)
    pin = _lms_pub(envelope)
    result = HybridSigner(SigningKeyset()).verify(
        PAYLOAD, envelope, expected_public_keys={ALG_LMS: pin}
    )
    assert result.ok is True
    assert result.verified[ALG_LMS] is True
    assert result.pinned == {ALG_LMS: True}
    assert result.quantum_resistant is True


def test_unpinned_verify_is_backward_compatible() -> None:
    envelope = HybridSigner(generate_keyset(hmac=False, lms=True)).sign(PAYLOAD)
    result = HybridSigner(SigningKeyset()).verify(PAYLOAD, envelope)
    # No pin requested -> previous self-attesting behaviour, and no pin record.
    assert result.ok is True
    assert result.pinned == {}


def test_pinning_rejects_a_substituted_signing_key() -> None:
    # Honest signer A publishes its key; an attacker re-signs the same payload
    # with their own key B and swaps in B's public key. Unpinned verification is
    # fooled; pinning to A's key rejects the forgery (fail closed).
    honest = HybridSigner(generate_keyset(hmac=False, lms=True)).sign(PAYLOAD)
    honest_pin = _lms_pub(honest)
    forged = HybridSigner(generate_keyset(hmac=False, lms=True)).sign(PAYLOAD)

    fooled = HybridSigner(SigningKeyset()).verify(PAYLOAD, forged)
    assert fooled.ok is True  # the gap: a self-attesting forgery passes unpinned

    rejected = HybridSigner(SigningKeyset()).verify(
        PAYLOAD, forged, expected_public_keys={ALG_LMS: honest_pin}
    )
    assert rejected.ok is False
    assert rejected.verified[ALG_LMS] is False
    assert rejected.pinned == {ALG_LMS: False}
    assert any("pinned-key mismatch" in note for note in rejected.notes)


def test_pinning_a_malformed_key_fails_closed() -> None:
    envelope = HybridSigner(generate_keyset(hmac=False, lms=True)).sign(PAYLOAD)
    result = HybridSigner(SigningKeyset()).verify(
        PAYLOAD, envelope, expected_public_keys={ALG_LMS: "!!! not base64 !!!"}
    )
    assert result.ok is False
    assert result.pinned == {ALG_LMS: False}
