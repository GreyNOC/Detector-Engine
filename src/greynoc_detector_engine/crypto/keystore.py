"""A managed, on-disk keystore for hybrid signing keys.

This module centralises the single most dangerous operation in the engine's
post-quantum signing stack: persisting the state of a *stateful* hash-based
signature key (LMS / HSS, RFC 8554 / NIST SP 800-208). Such a key holds a
counter ``q`` into a tree of one-time leaves, and reusing any leaf -- signing two
distinct messages under the same leaf -- lets an attacker forge a third
signature. The standard mitigation is unforgiving: the advanced private state
MUST reach durable storage *before* the signature it produced is released.

:class:`Keystore` enforces exactly that. :meth:`Keystore.sign_artifact`

    1. loads the signer,
    2. signs (which advances the in-memory LMS counter),
    3. re-serialises the advanced key material and ``save()``\\s it to disk
       atomically,
    4. *then* returns the signature envelope.

A crash anywhere before step 4 simply loses the signature; it can never reuse a
leaf, because the on-disk counter is only ever moved forward and the signature
is withheld until that move is durable.

The store also tracks public, auditable :class:`KeyMetadata` (no secret bytes)
and supports generation, rotation, and compromise marking. Secret material is
serialised JSON-safely: HMAC / Ed25519 / ML-DSA bytes as base64, and the LMS/HSS
private key via :meth:`HssPrivateKey.to_dict`.

Persisted shape::

    {"version": 1, "keys": {<key_id>: {"metadata": {...}, "material": {...}}}}

Secrets live in this file, so :meth:`Keystore.save` writes atomically (temp file
then ``os.replace``) and best-effort restricts the file mode to ``0o600``. On
POSIX that is enforced; on Windows ``os.chmod`` only toggles the read-only bit,
so the restriction is advisory there -- protect the containing directory with
filesystem ACLs in production.
"""

from __future__ import annotations

import base64
import contextlib
import json
import os
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from greynoc_detector_engine.crypto import hbs
from greynoc_detector_engine.crypto.signing import (
    ALG_ED25519,
    ALG_HMAC,
    ALG_LMS,
    ALG_MLDSA,
    HybridSigner,
    SignatureEnvelope,
    SigningKeyset,
    ed25519_available,
    generate_keyset,
    mldsa_available,
)
from greynoc_detector_engine.models.crypto import KeyMetadata, KeyState

if TYPE_CHECKING:
    from collections.abc import Iterable

_STORE_VERSION = 1
_DEFAULT_ALGORITHMS: tuple[str, ...] = ("hmac", "lms")

# Algorithms whose presence makes a managed key post-quantum safe for signing.
_QUANTUM_SAFE_ALGORITHMS: frozenset[str] = frozenset({"lms", "mldsa"})

# Human-readable per-backend algorithm labels for KeyMetadata.algorithm.
_ALGORITHM_LABELS: dict[str, str] = {
    "hmac": ALG_HMAC,
    "ed25519": ALG_ED25519,
    "mldsa": ALG_MLDSA,
    "lms": ALG_LMS,
}

# Deterministic ordering for the algorithm summary regardless of request order.
_ALGORITHM_ORDER: tuple[str, ...] = ("hmac", "ed25519", "mldsa", "lms")


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def _as_str(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError(f"expected a str, got {type(value).__name__}")
    return value


def _as_dict(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"expected a dict, got {type(value).__name__}")
    return value


class KeystoreError(RuntimeError):
    """Raised for keystore-level problems (duplicate / unknown / exhausted keys)."""


class Keystore:
    """A persistent, on-disk store of hybrid signing keys.

    Construct with a path; the JSON file is loaded lazily if it already exists.
    Mutating operations (:meth:`generate_key`, :meth:`sign_artifact`,
    :meth:`rotate_key`, :meth:`mark_compromised`) persist to disk before
    returning, so the on-disk state is always at least as advanced as any
    signature that has been handed out.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        # entry := {"metadata": KeyMetadata, "material": dict[str, object]}
        self._keys: dict[str, dict[str, object]] = {}
        self._loaded = False

    # -- persistence -------------------------------------------------------

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        if self._path.exists():
            self._load()
        self._loaded = True

    def _load(self) -> None:
        raw = json.loads(self._path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise KeystoreError(f"keystore at {self._path} is not a JSON object")
        version = raw.get("version")
        if version != _STORE_VERSION:
            raise KeystoreError(
                f"unsupported keystore version {version!r} (expected {_STORE_VERSION})"
            )
        keys_obj = raw.get("keys", {})
        if not isinstance(keys_obj, dict):
            raise KeystoreError("keystore 'keys' must be a JSON object")
        loaded: dict[str, dict[str, object]] = {}
        for key_id, entry_obj in keys_obj.items():
            entry = _as_dict(entry_obj)
            metadata = KeyMetadata.model_validate(_as_dict(entry["metadata"]))
            material = _as_dict(entry["material"])
            loaded[str(key_id)] = {"metadata": metadata, "material": material}
        self._keys = loaded

    def save(self) -> None:
        """Atomically persist the store to disk and best-effort restrict its mode.

        Writes to a temporary file in the destination directory and then
        ``os.replace``\\s it over the target, so a reader never observes a
        half-written file and a crash cannot corrupt the store. The file mode is
        set to ``0o600`` where the platform honours it (POSIX); on Windows
        ``os.chmod`` only controls the read-only bit, so the restriction is
        best-effort and failures are ignored.
        """
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": _STORE_VERSION,
            "keys": {
                key_id: {
                    "metadata": _metadata_of(entry).model_dump(mode="json"),
                    "material": _material_of(entry),
                }
                for key_id, entry in self._keys.items()
            },
        }
        serialized = json.dumps(payload, indent=2, sort_keys=True)

        fd, tmp_name = tempfile.mkstemp(
            dir=str(self._path.parent), prefix=f".{self._path.name}.", suffix=".tmp"
        )
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(serialized)
                handle.flush()
                os.fsync(handle.fileno())
            _restrict_permissions(tmp_path)
            os.replace(tmp_path, self._path)
        except BaseException:
            tmp_path.unlink(missing_ok=True)
            raise
        _restrict_permissions(self._path)

    # -- generation --------------------------------------------------------

    def generate_key(self, key_id: str, *, algorithms: list[str] | None = None) -> KeyMetadata:
        """Generate and persist a fresh managed signing key.

        ``algorithms`` defaults to ``["hmac", "lms"]`` -- an always-available
        symmetric MAC plus a pure-stdlib post-quantum hash-based signature.
        Backends that are requested but unavailable in this environment
        (``ed25519`` needs ``cryptography``; ``mldsa`` needs ``oqs``) are skipped
        with a recorded note rather than raising, so a key can always be created.
        Refuses a duplicate ``key_id``.
        """
        self._ensure_loaded()
        if key_id in self._keys:
            raise KeystoreError(f"key_id {key_id!r} already exists in the keystore")

        requested = _normalize_algorithms(algorithms)
        notes: list[str] = []
        want_ed25519 = "ed25519" in requested
        want_mldsa = "mldsa" in requested
        if want_ed25519 and not ed25519_available():
            notes.append("ed25519 requested but the 'cryptography' backend is absent; skipped")
            want_ed25519 = False
        if want_mldsa and not mldsa_available():
            notes.append("mldsa requested but the 'oqs' (liboqs) backend is absent; skipped")
            want_mldsa = False

        keyset = generate_keyset(
            key_id,
            hmac="hmac" in requested,
            ed25519=want_ed25519,
            mldsa=want_mldsa,
            lms="lms" in requested,
        )
        material = _serialize_material(keyset)
        if not material:
            raise KeystoreError(
                f"no usable signing backend for key_id {key_id!r} (requested {sorted(requested)})"
            )

        active = _active_algorithms(keyset)
        metadata = KeyMetadata(
            key_id=key_id,
            algorithm=_algorithm_summary(active),
            quantum_safe=bool(_QUANTUM_SAFE_ALGORITHMS & active),
            state=KeyState.ACTIVE,
            public_key=_public_key_b64(keyset),
            signatures_remaining=(
                keyset.lms_private.remaining() if keyset.lms_private is not None else None
            ),
            usage=["sign", "verify"],
            notes=notes,
        )
        self._keys[key_id] = {"metadata": metadata, "material": material}
        self.save()
        return metadata

    # -- signing -----------------------------------------------------------

    def get_signer(self, key_id: str) -> HybridSigner:
        """Reconstruct a :class:`HybridSigner` for verification / stateless signing.

        The returned signer is intentionally **stripped of the stateful LMS/HSS
        key**: producing an LMS signature advances one-time-key state that only
        :meth:`sign_artifact` durably persists, so allowing a caller to sign LMS
        through a bare signer here would risk silent leaf reuse on the next reload.
        This signer can still *verify* LMS signatures (the public key travels in
        the envelope) and can sign with stateless backends (HMAC, Ed25519,
        ML-DSA). For post-quantum LMS signing use :meth:`sign_artifact`.
        """
        entry = self._entry(key_id)
        keyset = _deserialize_material(key_id, _material_of(entry))
        keyset.lms_private = None  # no stateful signing outside sign_artifact()
        return HybridSigner(keyset)

    def sign_artifact(self, key_id: str, payload: bytes) -> SignatureEnvelope:
        """Sign ``payload`` and durably persist the advanced key state first.

        The critical ordering: the signer advances the stateful LMS/HSS counter
        while signing, so the new key state is re-serialised and ``save()``\\d to
        disk *before* this method returns. A crash after the signature is
        produced but before it is returned therefore cannot lead to leaf reuse --
        the persisted counter has already moved forward.
        """
        entry = self._entry(key_id)
        metadata = _metadata_of(entry)
        if metadata.state is not KeyState.ACTIVE:
            raise KeystoreError(
                f"key_id {key_id!r} is {metadata.state.value}; refusing to sign with it"
            )

        keyset = _deserialize_material(key_id, _material_of(entry))
        signer = HybridSigner(keyset)
        try:
            envelope = signer.sign(payload)
        except RuntimeError as exc:
            # Surface exhaustion / no-backend clearly and flip the metadata so a
            # caller cannot keep hammering an exhausted stateful key.
            if keyset.lms_private is not None and keyset.lms_private.remaining() <= 0:
                metadata.state = KeyState.EXHAUSTED
                metadata.signatures_remaining = 0
                self.save()
            raise KeystoreError(f"signing with key_id {key_id!r} failed: {exc}") from exc

        # Re-serialise the now-advanced material and update the public budget,
        # then persist BEFORE returning the envelope (no-leaf-reuse guarantee).
        entry["material"] = _serialize_material(keyset)
        if keyset.lms_private is not None:
            remaining = keyset.lms_private.remaining()
            metadata.signatures_remaining = remaining
            if remaining <= 0:
                metadata.state = KeyState.EXHAUSTED
        self.save()
        return envelope

    # -- lifecycle ---------------------------------------------------------

    def rotate_key(
        self, old_key_id: str, new_key_id: str, *, algorithms: list[str] | None = None
    ) -> KeyMetadata:
        """Generate ``new_key_id`` and retire ``old_key_id``.

        The new key records ``rotated_from = old_key_id``; the old key's metadata
        moves to :data:`KeyState.RETIRED`. Both changes are persisted atomically.
        """
        self._ensure_loaded()
        old_entry = self._entry(old_key_id)
        if new_key_id in self._keys:
            raise KeystoreError(f"key_id {new_key_id!r} already exists in the keystore")

        new_metadata = self.generate_key(new_key_id, algorithms=algorithms)
        new_metadata.rotated_from = old_key_id
        old_metadata = _metadata_of(old_entry)
        if old_metadata.state is KeyState.ACTIVE:
            old_metadata.state = KeyState.RETIRED
        self.save()
        return new_metadata

    def mark_compromised(self, key_id: str) -> None:
        """Flag ``key_id`` as :data:`KeyState.COMPROMISED` and persist."""
        entry = self._entry(key_id)
        _metadata_of(entry).state = KeyState.COMPROMISED
        self.save()

    # -- read-only views ---------------------------------------------------

    def list_keys(self) -> list[KeyMetadata]:
        """Return public metadata for every key (never any secret material)."""
        self._ensure_loaded()
        return [_metadata_of(entry) for entry in self._keys.values()]

    def get_metadata(self, key_id: str) -> KeyMetadata:
        """Return the public metadata for ``key_id``."""
        return _metadata_of(self._entry(key_id))

    # -- internals ---------------------------------------------------------

    def _entry(self, key_id: str) -> dict[str, object]:
        self._ensure_loaded()
        entry = self._keys.get(key_id)
        if entry is None:
            raise KeystoreError(f"unknown key_id {key_id!r}")
        return entry


# --------------------------------------------------------------------------- #
# Entry accessors (typed views over the loosely-typed in-memory entry dicts)   #
# --------------------------------------------------------------------------- #


def _metadata_of(entry: dict[str, object]) -> KeyMetadata:
    metadata = entry["metadata"]
    if not isinstance(metadata, KeyMetadata):
        raise KeystoreError("keystore entry has a malformed 'metadata' value")
    return metadata


def _material_of(entry: dict[str, object]) -> dict[str, object]:
    return _as_dict(entry["material"])


# --------------------------------------------------------------------------- #
# Algorithm bookkeeping                                                        #
# --------------------------------------------------------------------------- #


def _normalize_algorithms(algorithms: list[str] | None) -> set[str]:
    if algorithms is None:
        return set(_DEFAULT_ALGORITHMS)
    normalized = {alg.strip().lower() for alg in algorithms if alg.strip()}
    if not normalized:
        return set(_DEFAULT_ALGORITHMS)
    unknown = normalized - set(_ALGORITHM_LABELS)
    if unknown:
        raise KeystoreError(f"unknown signing algorithm(s): {sorted(unknown)}")
    return normalized


def _active_algorithms(keyset: SigningKeyset) -> set[str]:
    """Which backends the keyset actually carries usable material for."""
    active: set[str] = set()
    if keyset.hmac_key is not None:
        active.add("hmac")
    if keyset.ed25519_private_bytes is not None:
        active.add("ed25519")
    if keyset.mldsa_secret_key is not None:
        active.add("mldsa")
    if keyset.lms_private is not None:
        active.add("lms")
    return active


def _algorithm_summary(active: Iterable[str]) -> str:
    present = set(active)
    labels = [_ALGORITHM_LABELS[name] for name in _ALGORITHM_ORDER if name in present]
    return "+".join(labels) if labels else "none"


def _public_key_b64(keyset: SigningKeyset) -> str | None:
    """The auditable public key: prefer the LMS/HSS root, else Ed25519."""
    if keyset.lms_private is not None:
        return _b64e(keyset.lms_private.public_key().to_bytes())
    if keyset.ed25519_public_bytes is not None:
        return _b64e(keyset.ed25519_public_bytes)
    return None


# --------------------------------------------------------------------------- #
# Secret-material (de)serialisation                                            #
# --------------------------------------------------------------------------- #


def _serialize_material(keyset: SigningKeyset) -> dict[str, object]:
    """Serialise a keyset's secret material to a JSON-safe dict.

    HMAC / Ed25519 / ML-DSA bytes become base64 strings; the stateful LMS/HSS
    key is serialised via its own :meth:`HssPrivateKey.to_dict`, which captures
    every tree's leaf counter so a reload never rolls state back.
    """
    material: dict[str, object] = {"key_id": keyset.key_id}
    if keyset.hmac_key is not None:
        material["hmac_key"] = _b64e(keyset.hmac_key)
    if keyset.ed25519_private_bytes is not None:
        material["ed25519_private"] = _b64e(keyset.ed25519_private_bytes)
    if keyset.ed25519_public_bytes is not None:
        material["ed25519_public"] = _b64e(keyset.ed25519_public_bytes)
    if keyset.mldsa_secret_key is not None:
        material["mldsa_secret"] = _b64e(keyset.mldsa_secret_key)
    if keyset.mldsa_public_key is not None:
        material["mldsa_public"] = _b64e(keyset.mldsa_public_key)
    material["mldsa_algorithm"] = keyset.mldsa_algorithm
    if keyset.lms_private is not None:
        material["lms_private"] = keyset.lms_private.to_dict()
    return material


def _deserialize_material(key_id: str, material: dict[str, object]) -> SigningKeyset:
    """Rebuild a :class:`SigningKeyset` from stored material.

    Crucially restores the stateful LMS/HSS key via
    :meth:`HssPrivateKey.from_dict`, so the advanced leaf counter persisted by a
    prior :meth:`Keystore.sign_artifact` is honoured.
    """
    keyset = SigningKeyset(key_id=_as_str(material.get("key_id", key_id)))
    if "hmac_key" in material:
        keyset.hmac_key = _b64d(_as_str(material["hmac_key"]))
    if "ed25519_private" in material:
        keyset.ed25519_private_bytes = _b64d(_as_str(material["ed25519_private"]))
    if "ed25519_public" in material:
        keyset.ed25519_public_bytes = _b64d(_as_str(material["ed25519_public"]))
    if "mldsa_secret" in material:
        keyset.mldsa_secret_key = _b64d(_as_str(material["mldsa_secret"]))
    if "mldsa_public" in material:
        keyset.mldsa_public_key = _b64d(_as_str(material["mldsa_public"]))
    if "mldsa_algorithm" in material:
        keyset.mldsa_algorithm = _as_str(material["mldsa_algorithm"])
    if "lms_private" in material:
        keyset.lms_private = hbs.HssPrivateKey.from_dict(_as_dict(material["lms_private"]))
    return keyset


def _restrict_permissions(path: Path) -> None:
    """Best-effort restrict ``path`` to owner-only read/write (``0o600``).

    On POSIX this is enforced. On Windows ``os.chmod`` only toggles the read-only
    attribute and cannot express owner-only access, so any failure is ignored --
    callers must rely on directory ACLs there. See the module docstring.
    """
    # Windows / restricted filesystems: advisory only, never fatal.
    with contextlib.suppress(OSError):
        os.chmod(path, 0o600)
