"""Content hashing with crypto-agility and an honest post-quantum posture.

The engine hashes content for de-duplication, fingerprints, and signature
payload digests. None of those uses needs a *secret*, but they all benefit from
being **algorithm-agile** (selectable, upgradable) and from avoiding broken
primitives.

Post-quantum note: hash functions are only weakened *quadratically* by Grover's
algorithm, so a 256-bit digest still offers ~128-bit preimage resistance against
a quantum adversary -- acceptable under NIST/CNSA-2.0 guidance. SHA-256, the
SHA-3 family, and BLAKE2 are therefore all quantum-resistant; SHA-1 and MD5 are
broken regardless and are refused.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

DEFAULT_HASH_ALGORITHM = "sha256"

# Digests with adequate residual security against a quantum (Grover) adversary.
QUANTUM_RESISTANT_HASHES: frozenset[str] = frozenset(
    {
        "sha256",
        "sha384",
        "sha512",
        "sha3_256",
        "sha3_384",
        "sha3_512",
        "blake2b",
        "blake2s",
    }
)

# Primitives that must never be used for integrity here.
_FORBIDDEN_HASHES: frozenset[str] = frozenset({"md5", "sha1", "md4", "ripemd160"})


def _resolve_algorithm(algorithm: str) -> str:
    name = algorithm.lower()
    if name in _FORBIDDEN_HASHES:
        raise ValueError(f"refusing to use cryptographically broken hash {algorithm!r}")
    if name not in hashlib.algorithms_available:
        raise ValueError(f"unsupported hash algorithm {algorithm!r}")
    return name


def is_quantum_resistant_hash(algorithm: str = DEFAULT_HASH_ALGORITHM) -> bool:
    """Whether ``algorithm`` retains adequate strength against a quantum adversary."""
    return algorithm.lower() in QUANTUM_RESISTANT_HASHES


def digest_bytes(data: bytes, *, algorithm: str = DEFAULT_HASH_ALGORITHM) -> str:
    """Full hex digest of raw bytes under the named algorithm."""
    return hashlib.new(_resolve_algorithm(algorithm), data).hexdigest()


def stable_hash(value: str, length: int = 16, *, algorithm: str = DEFAULT_HASH_ALGORITHM) -> str:
    digest = hashlib.new(_resolve_algorithm(algorithm), value.encode("utf-8")).hexdigest()
    return digest[:length]


def canonical_json_hash(
    value: Any, length: int = 16, *, algorithm: str = DEFAULT_HASH_ALGORITHM
) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return stable_hash(canonical, length=length, algorithm=algorithm)
