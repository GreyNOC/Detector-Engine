from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from greynoc_detector_engine.crypto.signing import (
    ALG_LMS,
    HybridSigner,
    SigningKeyset,
    generate_keyset,
)
from greynoc_detector_engine.crypto.transparency import (
    InclusionProof,
    LogEntry,
    SignedCheckpoint,
    TransparencyLog,
    checkpoint_public_keys,
    merkle_leaf_hash,
    merkle_node_hash,
    merkle_root,
)

ARTIFACTS: list[bytes] = [
    b"detection-bundle-v1",
    b"cbom-export",
    b"advisory-2026-001",
    b"yara-ruleset",
    b"sigma-ruleset",
]


def _signer() -> HybridSigner:
    return HybridSigner(generate_keyset(hmac=True, lms=True))


# --------------------------------------------------------------------------- #
# Pure Merkle functions                                                        #
# --------------------------------------------------------------------------- #


def test_empty_tree_root_is_hash_of_empty_string() -> None:
    assert merkle_root([]).hex() == hashlib.sha256(b"").hexdigest()


def test_leaf_and_node_use_rfc6962_domain_separation() -> None:
    leaf = merkle_leaf_hash(b"x")
    assert leaf.hex() == hashlib.sha256(b"\x00x").hexdigest()
    node = merkle_node_hash(b"a" * 32, b"b" * 32)
    assert node.hex() == hashlib.sha256(b"\x01" + b"a" * 32 + b"b" * 32).hexdigest()
    # A single leaf is its own root (no node hashing applied).
    assert merkle_root([leaf]) == leaf


def test_two_leaf_root_matches_manual_construction() -> None:
    left = merkle_leaf_hash(b"a")
    right = merkle_leaf_hash(b"b")
    assert merkle_root([left, right]) == merkle_node_hash(left, right)


# --------------------------------------------------------------------------- #
# Append / root stability                                                      #
# --------------------------------------------------------------------------- #


def test_append_five_artifacts_gives_stable_nonempty_root(tmp_path: Path) -> None:
    log = TransparencyLog(tmp_path / "log.jsonl")
    empty_root = log.root()
    for i, artifact in enumerate(ARTIFACTS):
        entry = log.append(f"artifact-{i}", artifact)
        assert isinstance(entry, LogEntry)
        assert entry.index == i
    assert log.size() == 5
    root = log.root()
    assert root
    assert root != empty_root
    # Stable: recomputing without mutation yields the same root.
    assert log.root() == root
    assert len(log.entries()) == 5


def test_entry_records_digest_and_leaf_hash(tmp_path: Path) -> None:
    log = TransparencyLog(tmp_path / "log.jsonl")
    entry = log.append("a", b"payload")
    assert entry.artifact_digest == hashlib.sha256(b"payload").hexdigest()
    assert entry.leaf_hash == merkle_leaf_hash(b"payload").hex()


def test_append_accepts_precomputed_hex_digest(tmp_path: Path) -> None:
    log = TransparencyLog(tmp_path / "log.jsonl")
    digest = hashlib.sha256(b"already-hashed").hexdigest()
    entry = log.append("precomputed", digest)
    assert entry.artifact_digest == digest
    # The leaf commits to the digest string's bytes.
    assert entry.leaf_hash == merkle_leaf_hash(digest.encode("ascii")).hex()


def test_append_rejects_non_hex_string(tmp_path: Path) -> None:
    log = TransparencyLog(tmp_path / "log.jsonl")
    with pytest.raises(ValueError, match="raw bytes or an even-length hex digest"):
        log.append("bad", "not-a-hex-digest!!")


# --------------------------------------------------------------------------- #
# Inclusion proofs                                                             #
# --------------------------------------------------------------------------- #


def test_inclusion_proof_for_each_index_verifies(tmp_path: Path) -> None:
    log = TransparencyLog(tmp_path / "log.jsonl")
    for i, artifact in enumerate(ARTIFACTS):
        log.append(f"artifact-{i}", artifact)
    root = log.root()
    for i in range(log.size()):
        proof = log.inclusion_proof(i)
        assert proof.leaf_index == i
        assert proof.tree_size == 5
        assert log.verify_inclusion(proof, root) is True


def test_wrong_leaf_fails_verification(tmp_path: Path) -> None:
    log = TransparencyLog(tmp_path / "log.jsonl")
    for i, artifact in enumerate(ARTIFACTS):
        log.append(f"artifact-{i}", artifact)
    root = log.root()
    proof = log.inclusion_proof(2)
    forged = InclusionProof(
        leaf_index=proof.leaf_index,
        tree_size=proof.tree_size,
        leaf_hash=merkle_leaf_hash(b"a-leaf-that-was-never-logged").hex(),
        audit_path=proof.audit_path,
    )
    assert log.verify_inclusion(forged, root) is False
    # A proof against the wrong root also fails.
    assert log.verify_inclusion(proof, merkle_leaf_hash(b"wrong-root").hex()) is False


def test_proof_for_single_entry_has_empty_path(tmp_path: Path) -> None:
    log = TransparencyLog(tmp_path / "log.jsonl")
    log.append("solo", b"only-one")
    proof = log.inclusion_proof(0)
    assert proof.audit_path == []
    assert log.verify_inclusion(proof, log.root()) is True


def test_inclusion_proof_out_of_range(tmp_path: Path) -> None:
    log = TransparencyLog(tmp_path / "log.jsonl")
    log.append("a", b"x")
    with pytest.raises(IndexError):
        log.inclusion_proof(5)


def test_verify_inclusion_tolerates_bad_hex(tmp_path: Path) -> None:
    log = TransparencyLog(tmp_path / "log.jsonl")
    log.append("a", b"x")
    bad = InclusionProof(leaf_index=0, tree_size=1, leaf_hash="zz", audit_path=[])
    assert log.verify_inclusion(bad, log.root()) is False


# --------------------------------------------------------------------------- #
# Signed checkpoints                                                           #
# --------------------------------------------------------------------------- #


def test_sign_and_verify_checkpoint(tmp_path: Path) -> None:
    log = TransparencyLog(tmp_path / "log.jsonl")
    for i, artifact in enumerate(ARTIFACTS):
        log.append(f"artifact-{i}", artifact)
    signer = _signer()
    checkpoint = log.sign_checkpoint(signer)
    assert isinstance(checkpoint, SignedCheckpoint)
    assert checkpoint.tree_size == 5
    assert checkpoint.root_hash == log.root()
    assert checkpoint.signature.quantum_resistant is True
    assert TransparencyLog.verify_checkpoint(checkpoint, signer) is True


def test_verify_checkpoint_pins_the_log_key_and_rejects_a_forgery(tmp_path: Path) -> None:
    log = TransparencyLog(tmp_path / "log.jsonl")
    for i, artifact in enumerate(ARTIFACTS):
        log.append(f"artifact-{i}", artifact)

    # The honest log signs with its (publishable) LMS key.
    honest = HybridSigner(generate_keyset(hmac=False, lms=True))
    checkpoint = log.sign_checkpoint(honest)
    log_key = checkpoint_public_keys(checkpoint)[ALG_LMS]
    empty = HybridSigner(SigningKeyset())

    # Pinning the published key authenticates the signed tree head.
    assert TransparencyLog.verify_checkpoint(
        checkpoint, empty, expected_public_keys={ALG_LMS: log_key}
    )

    # An attacker mints their OWN LMS key and signs the very same tree head.
    forged = log.sign_checkpoint(HybridSigner(generate_keyset(hmac=False, lms=True)))
    assert forged.root_hash == checkpoint.root_hash  # same root, different signer

    # Without pinning the forgery is accepted (the gap pinning closes)...
    assert TransparencyLog.verify_checkpoint(forged, empty) is True
    # ...but pinned to the real log key, the forged checkpoint is rejected.
    assert (
        TransparencyLog.verify_checkpoint(forged, empty, expected_public_keys={ALG_LMS: log_key})
        is False
    )


def test_checkpoint_round_trips_through_json(tmp_path: Path) -> None:
    log = TransparencyLog(tmp_path / "log.jsonl")
    log.append("a", b"x")
    signer_secret = generate_keyset(hmac=True)  # deterministic HMAC component
    signer = HybridSigner(signer_secret)
    checkpoint = log.sign_checkpoint(signer)
    restored = SignedCheckpoint.model_validate_json(checkpoint.model_dump_json())
    assert restored.root_hash == checkpoint.root_hash
    assert TransparencyLog.verify_checkpoint(restored, signer) is True


# --------------------------------------------------------------------------- #
# Tamper-evidence                                                              #
# --------------------------------------------------------------------------- #


def test_tampering_with_a_past_entry_changes_the_root(tmp_path: Path) -> None:
    path = tmp_path / "log.jsonl"
    log = TransparencyLog(path)
    for i, artifact in enumerate(ARTIFACTS):
        log.append(f"artifact-{i}", artifact)
    signer = _signer()
    checkpoint = log.sign_checkpoint(signer)
    original_root = log.root()

    # The signature itself is (and remains) valid over the *old* tree head...
    assert TransparencyLog.verify_checkpoint(checkpoint, signer) is True

    # ...but tampering with a past entry on disk changes the rebuilt root, so the
    # old checkpoint root no longer matches the live log.
    lines = path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[1])
    record["artifact_digest"] = hashlib.sha256(b"swapped-payload").hexdigest()
    record["leaf_hash"] = merkle_leaf_hash(b"swapped-payload").hex()
    lines[1] = json.dumps(record)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    reloaded = TransparencyLog(path)
    assert reloaded.root() != original_root
    # The previously-signed checkpoint root is now stale relative to the log:
    # tamper-evidence holds even though the signature over the old root verifies.
    assert checkpoint.root_hash != reloaded.root()
    assert checkpoint.root_hash == original_root


# --------------------------------------------------------------------------- #
# Persistence                                                                  #
# --------------------------------------------------------------------------- #


def test_reload_preserves_entries_and_root(tmp_path: Path) -> None:
    path = tmp_path / "log.jsonl"
    log = TransparencyLog(path)
    for i, artifact in enumerate(ARTIFACTS):
        log.append(f"artifact-{i}", artifact, metadata={"seq": str(i)})
    root_before = log.root()
    entries_before = log.entries()

    reloaded = TransparencyLog(path)
    assert reloaded.size() == 5
    assert reloaded.root() == root_before
    assert [e.leaf_hash for e in reloaded.entries()] == [e.leaf_hash for e in entries_before]
    assert reloaded.entries()[2].metadata == {"seq": "2"}
    # A proof built before the reload still verifies against the reloaded root.
    proof = log.inclusion_proof(3)
    assert reloaded.verify_inclusion(proof, reloaded.root()) is True


def test_appending_after_reload_continues_indices(tmp_path: Path) -> None:
    path = tmp_path / "log.jsonl"
    first = TransparencyLog(path)
    first.append("a", b"one")
    first.append("b", b"two")

    second = TransparencyLog(path)
    entry = second.append("c", b"three")
    assert entry.index == 2
    assert second.size() == 3
