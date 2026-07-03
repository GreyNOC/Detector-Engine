"""Append-only, Merkle-tree, tamper-evident transparency log of published artifacts.

This is a small RFC 6962-style "certificate transparency" log specialised for the
engine's published artifacts (detection bundles, CBOMs, advisories, ...). Every
artifact that ships is appended as a leaf; the log maintains a Merkle tree over
all leaves so that:

* any single past entry that is altered, reordered, or removed changes the
  Merkle root, and therefore invalidates any **previously signed checkpoint**
  (a post-quantum "signed tree head"), making tampering detectable; and
* an auditor can be handed a compact :class:`InclusionProof` for one artifact and
  verify -- with ``O(log n)`` hashes and *without* the whole log -- that the
  artifact is committed under a published root.

Design notes
------------
* **Hashing** is pure stdlib via :func:`greynoc_detector_engine.utils.hashing.
  digest_bytes`, with RFC 6962 domain separation so a leaf hash can never be
  confused with an interior node hash:

      leaf hash  = H(0x00 || data)
      node hash  = H(0x01 || left || right)
      empty tree = H(b"")        # RFC 6962 section 2.1

* **Checkpoints** are signed with the engine's :class:`~greynoc_detector_engine.
  crypto.signing.HybridSigner`, so the signed tree head carries a post-quantum
  (LMS/HSS and/or HMAC, optionally ML-DSA/Ed25519) signature out of the box. The
  signed bytes are the canonical JSON of ``{tree_size, root_hash}`` so the
  binding is stable and re-derivable by a verifier.

* **Persistence** is append-only JSONL at ``path`` -- one :class:`LogEntry` per
  line. Reloading rebuilds the in-memory tree from disk, so entries and the root
  survive a restart. No deletion or in-place rewrite API is offered; the only
  honest way to mutate history is to corrupt the file, which the tree detects.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field

from greynoc_detector_engine.crypto.signing import HybridSigner, SignatureEnvelope
from greynoc_detector_engine.utils.hashing import DEFAULT_HASH_ALGORITHM, digest_bytes
from greynoc_detector_engine.utils.time import utc_now

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

# RFC 6962 domain-separation prefixes.
_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"


# --------------------------------------------------------------------------- #
# Pure Merkle-tree functions (RFC 6962)                                        #
# --------------------------------------------------------------------------- #


def merkle_leaf_hash(data: bytes) -> bytes:
    """Return the RFC 6962 leaf hash ``H(0x00 || data)`` as raw bytes."""
    return bytes.fromhex(digest_bytes(_LEAF_PREFIX + data))


def merkle_node_hash(left: bytes, right: bytes) -> bytes:
    """Return the RFC 6962 interior node hash ``H(0x01 || left || right)``."""
    return bytes.fromhex(digest_bytes(_NODE_PREFIX + left + right))


def _empty_root() -> bytes:
    """The Merkle root of the empty tree: ``H(b"")`` (RFC 6962 section 2.1)."""
    return bytes.fromhex(digest_bytes(b""))


def merkle_root(leaves: list[bytes]) -> bytes:
    """Compute the RFC 6962 Merkle tree hash over ``leaves`` (raw leaf hashes).

    The empty tree hashes to ``H(b"")``. Otherwise the tree is built bottom-up
    with the RFC 6962 split rule: the left subtree holds the largest power of two
    strictly less than ``n`` leaves, the right subtree the remainder, so an
    odd node is promoted rather than duplicated.
    """
    if not leaves:
        return _empty_root()
    return _merkle_subtree(leaves)


def _largest_power_of_two_below(n: int) -> int:
    """Largest power of two strictly less than ``n`` (``n >= 2``)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _merkle_subtree(leaves: list[bytes]) -> bytes:
    """Merkle tree hash of a non-empty leaf list (RFC 6962 ``MTH``)."""
    if len(leaves) == 1:
        return leaves[0]
    k = _largest_power_of_two_below(len(leaves))
    left = _merkle_subtree(leaves[:k])
    right = _merkle_subtree(leaves[k:])
    return merkle_node_hash(left, right)


def merkle_inclusion_path(index: int, leaves: list[bytes]) -> list[bytes]:
    """Audit path (raw sibling hashes, leaf-to-root) for ``leaves[index]``.

    Follows RFC 6962 section 2.1.1 ``PATH(m, D[n])``.
    """
    n = len(leaves)
    if not 0 <= index < n:
        raise IndexError(f"leaf index {index} out of range for tree of size {n}")
    if n == 1:
        return []
    k = _largest_power_of_two_below(n)
    if index < k:
        return [*merkle_inclusion_path(index, leaves[:k]), _merkle_subtree(leaves[k:])]
    return [*merkle_inclusion_path(index - k, leaves[k:]), _merkle_subtree(leaves[:k])]


def verify_merkle_inclusion(
    leaf_hash: bytes, index: int, tree_size: int, audit_path: list[bytes], root: bytes
) -> bool:
    """Recompute the root from ``leaf_hash`` + ``audit_path`` and compare to ``root``.

    This is the RFC 6962 section 2.1.1 verification recurrence. ``fn`` tracks the
    node's index within its current sub-level and ``sn`` the index of the last
    node at that level; a sibling is folded in on the left when the node is a
    right child (``fn`` odd) and on the right when it is a left child, with the
    odd-promotion rule handled by skipping levels where the node has no sibling.
    """
    if not 0 <= index < tree_size:
        return False
    fn = index
    sn = tree_size - 1
    computed = leaf_hash
    for sibling in audit_path:
        if sn == 0:
            # More path elements than the tree height allows.
            return False
        if fn % 2 == 1 or fn == sn:
            computed = merkle_node_hash(sibling, computed)
            if fn % 2 == 0:
                # Odd-promoted node: climb until it becomes a right child.
                while fn % 2 == 0 and sn != 0:
                    fn //= 2
                    sn //= 2
        else:
            computed = merkle_node_hash(computed, sibling)
        fn //= 2
        sn //= 2
    return sn == 0 and computed == root


# --------------------------------------------------------------------------- #
# Models                                                                       #
# --------------------------------------------------------------------------- #


class LogEntry(BaseModel):
    """One committed artifact in the transparency log."""

    model_config = ConfigDict(extra="forbid")

    index: int = Field(ge=0)
    artifact_name: str
    artifact_digest: str  # hex digest of the artifact bytes under the log hash
    leaf_hash: str  # hex RFC 6962 leaf hash, H(0x00 || artifact_bytes)
    timestamp: datetime = Field(default_factory=utc_now)
    metadata: dict[str, str] = Field(default_factory=dict)


class SignedCheckpoint(BaseModel):
    """A signed tree head: the log's root at a point in time, with a PQ signature."""

    model_config = ConfigDict(extra="forbid")

    tree_size: int = Field(ge=0)
    root_hash: str  # hex Merkle root committing all ``tree_size`` entries
    timestamp: datetime = Field(default_factory=utc_now)
    signature: SignatureEnvelope


class InclusionProof(BaseModel):
    """A compact proof that one leaf is committed under a tree of a given size."""

    model_config = ConfigDict(extra="forbid")

    leaf_index: int = Field(ge=0)
    tree_size: int = Field(ge=1)
    leaf_hash: str  # hex RFC 6962 leaf hash of the proven entry
    audit_path: list[str] = Field(default_factory=list)  # hex sibling hashes


# --------------------------------------------------------------------------- #
# Canonical checkpoint bytes                                                   #
# --------------------------------------------------------------------------- #


def _checkpoint_payload(tree_size: int, root_hash: str) -> bytes:
    """Canonical, signer-stable bytes binding ``{tree_size, root_hash}``."""
    return json.dumps(
        {"tree_size": tree_size, "root_hash": root_hash},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def checkpoint_public_keys(checkpoint: SignedCheckpoint) -> dict[str, str]:
    """Return the ``{algorithm: base64 public key}`` a verifier should pin.

    A signed tree head only proves *origin* when the verifier pins the log's
    well-known public key; otherwise the embedded key is self-attesting and any
    party can forge a checkpoint over a tampered root. The log operator publishes
    this map once (out of band) and callers pin it on every subsequent
    :meth:`TransparencyLog.verify_checkpoint` via ``expected_public_keys``.
    """
    return {
        component.algorithm: component.public_key
        for component in checkpoint.signature.components
        if component.public_key is not None
    }


# --------------------------------------------------------------------------- #
# The log                                                                      #
# --------------------------------------------------------------------------- #


class TransparencyLog:
    """An append-only, Merkle-tree transparency log persisted as JSONL.

    The constructor loads any existing entries from ``path`` so a previously
    written log is restored verbatim (entries and root). Appending writes one
    JSON line per entry and updates the in-memory leaf list; the Merkle root is
    derived on demand from those leaves, so it always reflects the current state.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._entries: list[LogEntry] = []
        self._leaves: list[bytes] = []
        self._load()

    def _load(self) -> None:
        self._entries = []
        self._leaves = []
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if not stripped:
                    continue
                entry = LogEntry.model_validate_json(stripped)
                self._entries.append(entry)
                self._leaves.append(bytes.fromhex(entry.leaf_hash))

    @staticmethod
    def _is_hex_digest(value: str) -> bool:
        if not value:
            return False
        try:
            bytes.fromhex(value)
        except ValueError:
            return False
        return len(value) % 2 == 0

    def append(
        self,
        artifact_name: str,
        artifact: bytes | str,
        metadata: dict[str, str] | None = None,
    ) -> LogEntry:
        """Append an artifact and return its committed :class:`LogEntry`.

        ``artifact`` may be the raw artifact ``bytes`` *or* a precomputed hex
        digest string. Raw bytes are hashed with the log's default algorithm;
        the leaf hash is always the RFC 6962 leaf hash over the bytes that the
        digest represents. (For a precomputed digest we commit to the digest's
        own bytes -- the caller asserts that string *is* the artifact's identity.)
        """
        if isinstance(artifact, bytes):
            data = artifact
            artifact_digest = digest_bytes(data)
        else:
            if not self._is_hex_digest(artifact):
                raise ValueError("artifact must be raw bytes or an even-length hex digest string")
            artifact_digest = artifact.lower()
            data = artifact_digest.encode("ascii")

        leaf = merkle_leaf_hash(data)
        entry = LogEntry(
            index=len(self._entries),
            artifact_name=artifact_name,
            artifact_digest=artifact_digest,
            leaf_hash=leaf.hex(),
            metadata=dict(metadata or {}),
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(entry.model_dump_json() + "\n")
        self._entries.append(entry)
        self._leaves.append(leaf)
        return entry

    def size(self) -> int:
        """The number of committed entries (the current tree size)."""
        return len(self._entries)

    def entries(self) -> list[LogEntry]:
        """A copy of the committed entries in append order."""
        return list(self._entries)

    def root(self) -> str:
        """The current Merkle root as a hex string (empty tree -> ``H(b"")``)."""
        return merkle_root(self._leaves).hex()

    def inclusion_proof(self, index: int) -> InclusionProof:
        """Build an :class:`InclusionProof` for the entry at ``index``."""
        if not 0 <= index < len(self._entries):
            raise IndexError(f"index {index} out of range for log of size {len(self._entries)}")
        path = merkle_inclusion_path(index, self._leaves)
        return InclusionProof(
            leaf_index=index,
            tree_size=len(self._entries),
            leaf_hash=self._leaves[index].hex(),
            audit_path=[node.hex() for node in path],
        )

    def verify_inclusion(self, proof: InclusionProof, root_hex: str) -> bool:
        """Verify ``proof`` against ``root_hex`` by recomputing the root.

        Returns ``False`` (never raises) on any malformed hex or structural
        mismatch, so it is safe to call on untrusted proofs.
        """
        try:
            leaf = bytes.fromhex(proof.leaf_hash)
            audit_path = [bytes.fromhex(node) for node in proof.audit_path]
            root = bytes.fromhex(root_hex)
        except ValueError:
            return False
        return verify_merkle_inclusion(leaf, proof.leaf_index, proof.tree_size, audit_path, root)

    def sign_checkpoint(self, signer: HybridSigner) -> SignedCheckpoint:
        """Sign the current tree head, returning a :class:`SignedCheckpoint`."""
        return self.build_checkpoint(signer.sign)

    def build_checkpoint(self, sign: Callable[[bytes], SignatureEnvelope]) -> SignedCheckpoint:
        """Sign the current tree head with an arbitrary signing callable.

        ``sign`` receives the canonical checkpoint payload and returns its
        :class:`SignatureEnvelope`. This decouples the log from *where* the
        signing key lives, so a checkpoint can be signed by a persistent,
        pinnable keystore key -- e.g. ``log.build_checkpoint(lambda p:
        keystore.sign_artifact(key_id, p))`` -- which advances and durably
        persists stateful LMS/HSS state before the envelope is released. Pin the
        signer's public key on the verifying side (see :func:`checkpoint_public_keys`).
        """
        tree_size = len(self._entries)
        root_hash = self.root()
        envelope = sign(_checkpoint_payload(tree_size, root_hash))
        return SignedCheckpoint(
            tree_size=tree_size,
            root_hash=root_hash,
            signature=envelope,
        )

    @staticmethod
    def verify_checkpoint(
        checkpoint: SignedCheckpoint,
        signer: HybridSigner,
        *,
        expected_public_keys: Mapping[str, str] | None = None,
    ) -> bool:
        """Verify a checkpoint's signature over its bound ``{tree_size, root_hash}``.

        Pass ``expected_public_keys`` (algorithm -> base64 public key) to pin the
        log's well-known signing key: without a pin the embedded public key is
        self-attesting, so *anyone* can forge a checkpoint over a tampered root
        and it will verify. Pinning is what makes the signed tree head prove
        *origin* (RFC 6962-style), not merely internal consistency. Discover the
        key to pin once via :func:`checkpoint_public_keys`.

        Tamper-evidence is orthogonal and always holds: if any past entry changed,
        a freshly computed root no longer equals ``checkpoint.root_hash``, so a
        verifier comparing the live :meth:`root` to ``checkpoint.root_hash`` sees
        the mismatch even though the (still-valid) signature attests the old root.
        """
        payload = _checkpoint_payload(checkpoint.tree_size, checkpoint.root_hash)
        return signer.verify(
            payload, checkpoint.signature, expected_public_keys=expected_public_keys
        ).ok

    def hash_algorithm(self) -> str:
        """The hash algorithm used for leaves and digests (informational)."""
        return DEFAULT_HASH_ALGORITHM
