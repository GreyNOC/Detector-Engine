from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from greynoc_detector_engine.crypto.keystore import Keystore, KeystoreError
from greynoc_detector_engine.crypto.signing import ALG_LMS, HybridSigner, SigningKeyset
from greynoc_detector_engine.models.crypto import KeyState

PAYLOAD = b"GreyNOC Detector Engine detection bundle"


def _verify(payload: bytes, envelope: object) -> bool:
    # A verifier with no private keyset can still check the embedded LMS public key.
    from greynoc_detector_engine.crypto.signing import SignatureEnvelope

    assert isinstance(envelope, SignatureEnvelope)
    return HybridSigner(SigningKeyset()).verify(payload, envelope).ok


def test_generate_key_is_quantum_safe_and_persists(tmp_path: Path) -> None:
    store = Keystore(tmp_path / "keys.json")
    metadata = store.generate_key("primary")

    assert metadata.key_id == "primary"
    assert metadata.quantum_safe is True
    assert "hss-lms" in metadata.algorithm
    assert "hmac-sha256" in metadata.algorithm
    assert metadata.state is KeyState.ACTIVE
    assert metadata.public_key is not None
    assert metadata.signatures_remaining is not None and metadata.signatures_remaining > 0
    # The store wrote itself to disk.
    assert (tmp_path / "keys.json").exists()


def test_generate_key_refuses_duplicate(tmp_path: Path) -> None:
    store = Keystore(tmp_path / "keys.json")
    store.generate_key("primary")
    with pytest.raises(KeystoreError, match="already exists"):
        store.generate_key("primary")


def test_generate_key_rejects_unknown_algorithm(tmp_path: Path) -> None:
    store = Keystore(tmp_path / "keys.json")
    with pytest.raises(KeystoreError, match="unknown signing algorithm"):
        store.generate_key("primary", algorithms=["hmac", "rsa"])


def test_sign_artifact_verifies(tmp_path: Path) -> None:
    store = Keystore(tmp_path / "keys.json")
    store.generate_key("primary")
    envelope = store.sign_artifact("primary", PAYLOAD)

    assert ALG_LMS in envelope.algorithms
    assert envelope.quantum_resistant is True
    assert _verify(PAYLOAD, envelope) is True
    # And a reconstructed signer (with the secret keyset) also verifies.
    assert store.get_signer("primary").verify(PAYLOAD, envelope).ok is True


def test_stateful_lms_never_reuses_a_leaf_across_a_reload(tmp_path: Path) -> None:
    """The safety-critical invariant: persist advanced state before returning."""
    path = tmp_path / "keys.json"
    store = Keystore(path)
    store.generate_key("primary")
    before = store.get_metadata("primary").signatures_remaining
    assert before is not None

    first = store.sign_artifact("primary", PAYLOAD)

    # Re-open the store FROM DISK between signatures -- a fresh process would see
    # exactly this state. The persisted counter must already have advanced.
    reloaded = Keystore(path)
    mid = reloaded.get_metadata("primary").signatures_remaining
    assert mid is not None
    assert mid < before  # the first signature was durably accounted for

    second = reloaded.sign_artifact("primary", PAYLOAD)

    # Same payload, two distinct one-time leaves -> two distinct LMS signatures.
    first_lms = next(c for c in first.components if c.algorithm == ALG_LMS)
    second_lms = next(c for c in second.components if c.algorithm == ALG_LMS)
    assert first_lms.signature != second_lms.signature
    assert _verify(PAYLOAD, first) is True
    assert _verify(PAYLOAD, second) is True

    # The remaining budget is strictly monotonically decreasing across reloads and
    # signatures -- it never rolls back, which is the property that matters.
    final = Keystore(path)
    after = final.get_metadata("primary").signatures_remaining
    assert after is not None
    assert after < mid < before

    # The decisive no-leaf-reuse witness: the persisted bottom-tree message-leaf
    # counter q advanced to exactly the number of artifacts signed (2), on disk,
    # with no rollback across the reload that happened between the two signatures.
    on_disk = json.loads(path.read_text(encoding="utf-8"))
    lms_priv = on_disk["keys"]["primary"]["material"]["lms_private"]
    bottom_tree = lms_priv["trees"][-1]
    assert bottom_tree["q"] == 2


def test_rotate_key_retires_old_and_links_new(tmp_path: Path) -> None:
    store = Keystore(tmp_path / "keys.json")
    store.generate_key("primary")
    new_metadata = store.rotate_key("primary", "secondary")

    assert new_metadata.rotated_from == "primary"
    assert new_metadata.key_id == "secondary"
    assert store.get_metadata("primary").state is KeyState.RETIRED
    assert store.get_metadata("secondary").state is KeyState.ACTIVE

    # Rotation survives a reload.
    reloaded = Keystore(tmp_path / "keys.json")
    assert reloaded.get_metadata("primary").state is KeyState.RETIRED
    assert reloaded.get_metadata("secondary").rotated_from == "primary"


def test_rotate_into_existing_id_is_refused(tmp_path: Path) -> None:
    store = Keystore(tmp_path / "keys.json")
    store.generate_key("primary")
    store.generate_key("secondary")
    with pytest.raises(KeystoreError, match="already exists"):
        store.rotate_key("primary", "secondary")


def test_list_keys_exposes_metadata_without_secrets(tmp_path: Path) -> None:
    store = Keystore(tmp_path / "keys.json")
    store.generate_key("primary")
    store.generate_key("backup")

    keys = store.list_keys()
    assert {k.key_id for k in keys} == {"primary", "backup"}
    for metadata in keys:
        dumped = metadata.model_dump()
        # Public metadata only: no secret field names leak through.
        for secret_field in ("hmac_key", "lms_private", "ed25519_private", "mldsa_secret"):
            assert secret_field not in dumped


def test_mark_compromised_flips_state(tmp_path: Path) -> None:
    store = Keystore(tmp_path / "keys.json")
    store.generate_key("primary")
    store.mark_compromised("primary")

    assert store.get_metadata("primary").state is KeyState.COMPROMISED
    # Reload to confirm it persisted.
    assert Keystore(tmp_path / "keys.json").get_metadata("primary").state is KeyState.COMPROMISED


def test_sign_with_non_active_key_is_refused(tmp_path: Path) -> None:
    store = Keystore(tmp_path / "keys.json")
    store.generate_key("primary")
    store.mark_compromised("primary")
    with pytest.raises(KeystoreError, match="compromised"):
        store.sign_artifact("primary", PAYLOAD)


def test_unknown_key_operations_raise(tmp_path: Path) -> None:
    store = Keystore(tmp_path / "keys.json")
    with pytest.raises(KeystoreError, match="unknown key_id"):
        store.get_metadata("ghost")
    with pytest.raises(KeystoreError, match="unknown key_id"):
        store.sign_artifact("ghost", PAYLOAD)


def test_hmac_only_key_is_not_quantum_safe(tmp_path: Path) -> None:
    store = Keystore(tmp_path / "keys.json")
    metadata = store.generate_key("mac-only", algorithms=["hmac"])
    assert metadata.quantum_safe is False
    assert metadata.signatures_remaining is None  # symmetric MAC is unlimited
    assert "hmac-sha256" in metadata.algorithm


def test_rejected_corrupt_store_file(tmp_path: Path) -> None:
    path = tmp_path / "keys.json"
    path.write_text(json.dumps({"version": 99, "keys": {}}), encoding="utf-8")
    store = Keystore(path)
    with pytest.raises(KeystoreError, match="unsupported keystore version"):
        store.list_keys()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file mode not enforced on Windows")
def test_save_restricts_file_permissions(tmp_path: Path) -> None:
    import stat

    path = tmp_path / "keys.json"
    Keystore(path).generate_key("primary")
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600
