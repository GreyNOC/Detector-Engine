"""Pure-Python hash-based signatures: RFC 8554 LMS/LM-OTS and HSS.

This is the engine's *always-available* post-quantum signature backend. It
depends only on the standard library (``hashlib`` SHA-256) so it executes in
every environment regardless of whether liboqs / ML-DSA is installed. It is a
faithful implementation of:

* RFC 8554 -- Leighton-Micali Hash-Based Signatures (LM-OTS, LMS, HSS).
* NIST SP 800-208 Appendix A pseudorandom key generation, so that a private key
  is stored compactly as ``(I, SEED, q)`` rather than as a full table of
  one-time secrets.

Public surface (consumed by ``crypto.signing``):

    key = generate_lms_key(lms_type=LMS_SHA256_M32_H5)
    sig = key.sign(b"message")              # advances the leaf counter
    assert key.public_key().verify(b"message", sig)
    assert lms_verify(key.public_key().to_bytes(), b"message", sig)

    hss = generate_hss_key(levels=2)
    hsig = hss.sign(b"message")
    assert hss_verify(hss.public_key().to_bytes(), b"message", hsig)

STATEFUL HAZARD
---------------
LMS/HSS are *stateful* signatures. Every leaf (one-time key) MUST be used at
most once: signing two distinct messages with the same leaf lets an attacker
forge a third. ``LmsPrivateKey.sign`` therefore advances ``q`` on every call,
persists nothing implicitly, and raises ``RuntimeError`` once the tree is
exhausted (``q == 2**h``). Callers that serialise a key with ``to_dict`` and
later restore it MUST treat the serialised counter as authoritative and never
roll it back.

All integers are encoded big-endian: ``u32`` is 4 bytes, ``u16`` 2 bytes,
``u8`` 1 byte. The hash ``H`` is SHA-256 with output size ``n = 32``.
"""

from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass

# --- Hash primitive -------------------------------------------------------

_N = 32  # SHA-256 output size in bytes (== m == n for the parameter sets below)


def _h(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# --- Integer serialisation ------------------------------------------------


def _u8(value: int) -> bytes:
    return value.to_bytes(1, "big")


def _u16(value: int) -> bytes:
    return value.to_bytes(2, "big")


def _u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def _read_u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "big")


# --- Domain separators (RFC 8554 sections 4 and 5) ------------------------

_D_PBLC = 0x8080
_D_MESG = 0x8181
_D_LEAF = 0x8282
_D_INTR = 0x8383


# --- Parameter sets -------------------------------------------------------


@dataclass(frozen=True)
class _LmotsParams:
    """LM-OTS parameter set (RFC 8554 Table 1)."""

    type_code: int
    name: str
    n: int
    w: int
    p: int
    ls: int


# Type codes 0x01..0x04 -> W1, W2, W4, W8.
LMOTS_SHA256_N32_W1 = _LmotsParams(0x00000001, "LMOTS_SHA256_N32_W1", _N, 1, 265, 7)
LMOTS_SHA256_N32_W2 = _LmotsParams(0x00000002, "LMOTS_SHA256_N32_W2", _N, 2, 133, 6)
LMOTS_SHA256_N32_W4 = _LmotsParams(0x00000003, "LMOTS_SHA256_N32_W4", _N, 4, 67, 4)
LMOTS_SHA256_N32_W8 = _LmotsParams(0x00000004, "LMOTS_SHA256_N32_W8", _N, 8, 34, 0)

_LMOTS_BY_CODE: dict[int, _LmotsParams] = {
    p.type_code: p
    for p in (
        LMOTS_SHA256_N32_W1,
        LMOTS_SHA256_N32_W2,
        LMOTS_SHA256_N32_W4,
        LMOTS_SHA256_N32_W8,
    )
}


@dataclass(frozen=True)
class _LmsParams:
    """LMS parameter set (RFC 8554 Table 2)."""

    type_code: int
    name: str
    m: int
    h: int


# Type codes 0x05..0x09 -> H5, H10, H15, H20, H25.
LMS_SHA256_M32_H5 = _LmsParams(0x00000005, "LMS_SHA256_M32_H5", _N, 5)
LMS_SHA256_M32_H10 = _LmsParams(0x00000006, "LMS_SHA256_M32_H10", _N, 10)
LMS_SHA256_M32_H15 = _LmsParams(0x00000007, "LMS_SHA256_M32_H15", _N, 15)
LMS_SHA256_M32_H20 = _LmsParams(0x00000008, "LMS_SHA256_M32_H20", _N, 20)
LMS_SHA256_M32_H25 = _LmsParams(0x00000009, "LMS_SHA256_M32_H25", _N, 25)

_LMS_BY_CODE: dict[int, _LmsParams] = {
    p.type_code: p
    for p in (
        LMS_SHA256_M32_H5,
        LMS_SHA256_M32_H10,
        LMS_SHA256_M32_H15,
        LMS_SHA256_M32_H20,
        LMS_SHA256_M32_H25,
    )
}


def _lmots_params(type_code: int) -> _LmotsParams:
    params = _LMOTS_BY_CODE.get(type_code)
    if params is None:
        raise ValueError(f"unknown LM-OTS type code: 0x{type_code:08x}")
    return params


def _lms_params(type_code: int) -> _LmsParams:
    params = _LMS_BY_CODE.get(type_code)
    if params is None:
        raise ValueError(f"unknown LMS type code: 0x{type_code:08x}")
    return params


# --- LM-OTS core (RFC 8554 section 4) -------------------------------------


def _coef(s: bytes, i: int, w: int) -> int:
    """Return the i-th ``w``-bit coefficient of byte string ``s`` (RFC 4.2)."""
    mask = (1 << w) - 1
    shift = 8 - (w * (i % (8 // w)) + w)
    byte = s[(i * w) // 8]
    return (byte >> shift) & mask


def _checksum(s: bytes, params: _LmotsParams) -> int:
    """Cksm over the hash ``s`` (RFC 4.4, Algorithm 2)."""
    total = 0
    upper = (params.n * 8) // params.w
    max_digit = (1 << params.w) - 1
    for i in range(upper):
        total += max_digit - _coef(s, i, params.w)
    return (total << params.ls) & 0xFFFF


def _expanded_digits(q_hash: bytes, params: _LmotsParams) -> bytes:
    """Q || Cksm(Q) as a byte string for coefficient extraction."""
    return q_hash + _u16(_checksum(q_hash, params))


def _lmots_derive_x(identifier: bytes, q: int, seed: bytes, params: _LmotsParams) -> list[bytes]:
    """Derive the one-time secrets x[0..p-1] (SP 800-208 Appendix A)."""
    return [_h(identifier + _u32(q) + _u16(i) + _u8(0xFF) + seed) for i in range(params.p)]


def _lmots_public_k(identifier: bytes, q: int, x: list[bytes], params: _LmotsParams) -> bytes:
    """Compute the LM-OTS public key value K (RFC 4.3, Algorithm 1)."""
    end = (1 << params.w) - 1
    y_concat = bytearray()
    for i in range(params.p):
        tmp = x[i]
        for j in range(end):
            tmp = _h(identifier + _u32(q) + _u16(i) + _u8(j) + tmp)
        y_concat += tmp
    return _h(identifier + _u32(q) + _u16(_D_PBLC) + bytes(y_concat))


def _lmots_sign(
    identifier: bytes,
    q: int,
    seed: bytes,
    message: bytes,
    params: _LmotsParams,
    randomizer: bytes,
) -> bytes:
    """Generate an LM-OTS signature (RFC 4.5, Algorithm 3)."""
    x = _lmots_derive_x(identifier, q, seed, params)
    q_hash = _h(identifier + _u32(q) + _u16(_D_MESG) + randomizer + message)
    digits = _expanded_digits(q_hash, params)
    y_concat = bytearray()
    for i in range(params.p):
        a = _coef(digits, i, params.w)
        tmp = x[i]
        for j in range(a):
            tmp = _h(identifier + _u32(q) + _u16(i) + _u8(j) + tmp)
        y_concat += tmp
    return _u32(params.type_code) + randomizer + bytes(y_concat)


def _lmots_public_from_sig(
    identifier: bytes,
    q: int,
    message: bytes,
    signature: bytes,
    expected_type: int,
) -> bytes | None:
    """Compute candidate K from an LM-OTS signature (RFC 4.6, Algorithm 4b)."""
    if len(signature) < 4:
        return None
    sig_type = _read_u32(signature, 0)
    if sig_type != expected_type:
        return None
    params = _LMOTS_BY_CODE.get(sig_type)
    if params is None:
        return None
    if len(signature) != 4 + params.n * (params.p + 1):
        return None
    randomizer = signature[4 : 4 + params.n]
    y = [signature[4 + params.n * (k + 1) : 4 + params.n * (k + 2)] for k in range(params.p)]
    q_hash = _h(identifier + _u32(q) + _u16(_D_MESG) + randomizer + message)
    digits = _expanded_digits(q_hash, params)
    end = (1 << params.w) - 1
    z_concat = bytearray()
    for i in range(params.p):
        a = _coef(digits, i, params.w)
        tmp = y[i]
        for j in range(a, end):
            tmp = _h(identifier + _u32(q) + _u16(i) + _u8(j) + tmp)
        z_concat += tmp
    return _h(identifier + _u32(q) + _u16(_D_PBLC) + bytes(z_concat))


# --- LMS Merkle tree (RFC 8554 section 5) ---------------------------------


def _lms_leaf(identifier: bytes, q: int, k: bytes, h: int) -> bytes:
    """T[2^h + q] for a leaf holding LM-OTS public value ``k``."""
    node_num = (1 << h) + q
    return _h(identifier + _u32(node_num) + _u16(_D_LEAF) + k)


def _build_tree(
    identifier: bytes, seed: bytes, lms: _LmsParams, lmots: _LmotsParams
) -> list[bytes]:
    """Build the full node table T[1 .. 2^(h+1)-1] for an LMS tree."""
    leaves = 1 << lms.h
    tree: list[bytes] = [b""] * (2 * leaves)
    for q in range(leaves):
        x = _lmots_derive_x(identifier, q, seed, lmots)
        k = _lmots_public_k(identifier, q, x, lmots)
        tree[leaves + q] = _lms_leaf(identifier, q, k, lms.h)
    for r in range(leaves - 1, 0, -1):
        tree[r] = _h(identifier + _u32(r) + _u16(_D_INTR) + tree[2 * r] + tree[2 * r + 1])
    return tree


def _auth_path(tree: list[bytes], q: int, h: int) -> bytes:
    """Authentication path[0..h-1] for leaf ``q`` (RFC 5.4)."""
    path = bytearray()
    node = (1 << h) + q
    while node > 1:
        path += tree[node ^ 1]
        node //= 2
    return bytes(path)


def _lms_root_from_sig(public_key: bytes, message: bytes, signature: bytes) -> bytes | None:
    """Compute candidate LMS root Tc (RFC 5.4.2, Algorithm 6a)."""
    if len(public_key) < 8:
        return None
    lms_type = _read_u32(public_key, 0)
    ots_type = _read_u32(public_key, 4)
    lms = _LMS_BY_CODE.get(lms_type)
    if lms is None:
        return None
    if len(public_key) != 24 + lms.m:
        return None
    identifier = public_key[8:24]
    root = public_key[24 : 24 + lms.m]

    if len(signature) < 8:
        return None
    q = _read_u32(signature, 0)
    ots_sig_type = _read_u32(signature, 4)
    if ots_sig_type != ots_type:
        return None
    lmots = _LMOTS_BY_CODE.get(ots_sig_type)
    if lmots is None:
        return None
    ots_sig_len = 4 + lmots.n * (lmots.p + 1)
    if len(signature) < 12 + lmots.n * (lmots.p + 1):
        return None
    lmots_sig = signature[4 : 4 + ots_sig_len]
    sig_lms_type = _read_u32(signature, 4 + ots_sig_len)
    if sig_lms_type != lms_type:
        return None
    if q >= (1 << lms.h):
        return None
    if len(signature) != 12 + lmots.n * (lmots.p + 1) + lms.m * lms.h:
        return None
    path_off = 8 + ots_sig_len
    path = [signature[path_off + i * lms.m : path_off + (i + 1) * lms.m] for i in range(lms.h)]

    candidate_k = _lmots_public_from_sig(identifier, q, message, lmots_sig, ots_type)
    if candidate_k is None:
        return None

    node_num = (1 << lms.h) + q
    tmp = _h(identifier + _u32(node_num) + _u16(_D_LEAF) + candidate_k)
    for i in range(lms.h):
        if node_num % 2 == 1:
            tmp = _h(identifier + _u32(node_num // 2) + _u16(_D_INTR) + path[i] + tmp)
        else:
            tmp = _h(identifier + _u32(node_num // 2) + _u16(_D_INTR) + tmp + path[i])
        node_num //= 2
    if root != tmp:
        return None
    return tmp


def lms_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an LMS signature (RFC 5.4.2, Algorithm 6). Never raises."""
    try:
        return _lms_root_from_sig(public_key, message, signature) is not None
    except (ValueError, IndexError):
        return False


# --- Public key / private key classes -------------------------------------


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


class LmsPublicKey:
    """An LMS public key (56-byte wire format) that can verify signatures."""

    __slots__ = ("_identifier", "_lmots", "_lms", "_root")

    def __init__(
        self, lms: _LmsParams, lmots: _LmotsParams, identifier: bytes, root: bytes
    ) -> None:
        self._lms = lms
        self._lmots = lmots
        self._identifier = identifier
        self._root = root

    def to_bytes(self) -> bytes:
        return (
            _u32(self._lms.type_code) + _u32(self._lmots.type_code) + self._identifier + self._root
        )

    @classmethod
    def from_bytes(cls, b: bytes) -> LmsPublicKey:
        if len(b) < 8:
            raise ValueError("LMS public key is too short")
        lms = _lms_params(_read_u32(b, 0))
        lmots = _lmots_params(_read_u32(b, 4))
        if len(b) != 24 + lms.m:
            raise ValueError("LMS public key has an invalid length")
        return cls(lms, lmots, b[8:24], b[24 : 24 + lms.m])

    def verify(self, message: bytes, signature: bytes) -> bool:
        return lms_verify(self.to_bytes(), message, signature)

    @property
    def algorithm(self) -> str:
        return f"{self._lms.name}/{self._lmots.name}"


class LmsPrivateKey:
    """A stateful LMS private key. ``sign`` advances and refuses leaf reuse.

    The key is stored compactly as ``(I, SEED, q)`` per SP 800-208 Appendix A.
    The Merkle tree is built lazily (and cached) the first time a signature or
    public key is requested, because building it is the expensive step.
    """

    __slots__ = ("_identifier", "_lmots", "_lms", "_pub", "_q", "_seed", "_tree")

    def __init__(
        self,
        lms: _LmsParams,
        lmots: _LmotsParams,
        identifier: bytes,
        seed: bytes,
        q: int = 0,
    ) -> None:
        if len(identifier) != 16:
            raise ValueError("LMS identifier I must be 16 bytes")
        if len(seed) != lms.m:
            raise ValueError(f"LMS seed must be {lms.m} bytes")
        if not 0 <= q <= (1 << lms.h):
            raise ValueError("LMS leaf counter q is out of range")
        self._lms = lms
        self._lmots = lmots
        self._identifier = identifier
        self._seed = seed
        self._q = q
        self._tree: list[bytes] | None = None
        self._pub: LmsPublicKey | None = None

    def _ensure_tree(self) -> list[bytes]:
        if self._tree is None:
            self._tree = _build_tree(self._identifier, self._seed, self._lms, self._lmots)
        return self._tree

    def public_key(self) -> LmsPublicKey:
        if self._pub is None:
            tree = self._ensure_tree()
            self._pub = LmsPublicKey(self._lms, self._lmots, self._identifier, tree[1])
        return self._pub

    def remaining(self) -> int:
        return (1 << self._lms.h) - self._q

    def sign(self, message: bytes) -> bytes:
        """Sign ``message`` with the next leaf, then advance ``q``.

        Raises ``RuntimeError`` when the tree is exhausted. Each leaf is used at
        most once; the counter advances *before* the signature is returned.
        """
        if self._q >= (1 << self._lms.h):
            raise RuntimeError("LMS private key is exhausted: every one-time leaf has been used")
        tree = self._ensure_tree()
        q = self._q
        randomizer = os.urandom(self._lmots.n)
        lmots_sig = _lmots_sign(self._identifier, q, self._seed, message, self._lmots, randomizer)
        path = _auth_path(tree, q, self._lms.h)
        signature = _u32(q) + lmots_sig + _u32(self._lms.type_code) + path
        self._q = q + 1
        return signature

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": "lms",
            "lms_type": self._lms.type_code,
            "lmots_type": self._lmots.type_code,
            "identifier": _b64e(self._identifier),
            "seed": _b64e(self._seed),
            "q": self._q,
        }

    @classmethod
    def from_dict(cls, d: dict[str, object]) -> LmsPrivateKey:
        if d.get("kind") != "lms":
            raise ValueError("not an LMS private key dict")
        lms = _lms_params(int(_as_int(d["lms_type"])))
        lmots = _lmots_params(int(_as_int(d["lmots_type"])))
        identifier = _b64d(_as_str(d["identifier"]))
        seed = _b64d(_as_str(d["seed"]))
        q = int(_as_int(d["q"]))
        return cls(lms, lmots, identifier, seed, q)


# --- HSS wrapper (RFC 8554 section 6) --------------------------------------


def _lms_signature_length(signature: bytes, offset: int) -> int:
    """Return the byte length of the LMS signature starting at ``offset``."""
    q = _read_u32(signature, offset)
    del q
    ots_type = _read_u32(signature, offset + 4)
    lmots = _lmots_params(ots_type)
    ots_sig_len = 4 + lmots.n * (lmots.p + 1)
    lms_type = _read_u32(signature, offset + 4 + ots_sig_len)
    lms = _lms_params(lms_type)
    return 4 + ots_sig_len + 4 + lms.m * lms.h


def hss_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an HSS signature (RFC 6.3). Never raises on malformed input."""
    try:
        return _hss_verify_inner(public_key, message, signature)
    except (ValueError, IndexError):
        return False


def _lms_public_length(public_key: bytes, offset: int) -> int:
    """Return the byte length of the LMS public key starting at ``offset``."""
    lms_type = _read_u32(public_key, offset)
    lms = _lms_params(lms_type)
    return 24 + lms.m


def _hss_verify_inner(public_key: bytes, message: bytes, signature: bytes) -> bool:
    if len(public_key) < 4 or len(signature) < 4:
        return False
    levels = _read_u32(public_key, 0)
    nspk = _read_u32(signature, 0)
    if nspk + 1 != levels:
        return False

    # The signature is u32(Nspk) || (sig[i] || pub[i+1])* || sig[Nspk].
    # We climb the hierarchy: each signed sub-public-key must verify under the
    # public key established by the level above it.
    current_pub = public_key[4:]
    sig_off = 4
    for _ in range(nspk):
        lms_sig_len = _lms_signature_length(signature, sig_off)
        lms_sig = signature[sig_off : sig_off + lms_sig_len]
        sig_off += lms_sig_len
        next_pub_len = _lms_public_length(signature, sig_off)
        next_pub = signature[sig_off : sig_off + next_pub_len]
        sig_off += next_pub_len
        if not lms_verify(current_pub, next_pub, lms_sig):
            return False
        current_pub = next_pub
    final_sig = signature[sig_off:]
    return lms_verify(current_pub, message, final_sig)


class HssPublicKey:
    """An HSS public key: ``u32(L) || lms_public[level0]``."""

    __slots__ = ("_levels", "_lms_public")

    def __init__(self, levels: int, lms_public: LmsPublicKey) -> None:
        self._levels = levels
        self._lms_public = lms_public

    def to_bytes(self) -> bytes:
        return _u32(self._levels) + self._lms_public.to_bytes()

    @classmethod
    def from_bytes(cls, b: bytes) -> HssPublicKey:
        if len(b) < 4:
            raise ValueError("HSS public key is too short")
        levels = _read_u32(b, 0)
        return cls(levels, LmsPublicKey.from_bytes(b[4:]))

    def verify(self, message: bytes, signature: bytes) -> bool:
        return hss_verify(self.to_bytes(), message, signature)

    @property
    def algorithm(self) -> str:
        return f"HSS-L{self._levels}/{self._lms_public.algorithm}"


class HssPrivateKey:
    """A stateful HSS private key whose bottom tree advances per message.

    For ``L == 1`` this is a thin wrapper over a single LMS tree. For ``L >= 2``
    the upper trees sign the public keys of the trees below them; when the
    bottom tree exhausts, the next tree is regenerated and re-signed. The
    serialised form captures every tree's counter so a restored key never
    reuses a leaf.
    """

    __slots__ = ("_levels", "_lmots_type", "_lms_type", "_signed_pubs", "_trees")

    def __init__(
        self,
        levels: int,
        trees: list[LmsPrivateKey],
        lms_type: _LmsParams,
        lmots_type: _LmotsParams,
        signed_pubs: list[tuple[bytes, bytes]] | None = None,
    ) -> None:
        if levels < 1:
            raise ValueError("HSS requires at least one level")
        if len(trees) != levels:
            raise ValueError("HSS tree count must match the number of levels")
        self._levels = levels
        self._trees = trees
        self._lms_type = lms_type
        self._lmots_type = lmots_type
        # signed_pubs[i] = (pub_bytes[i+1], sig over it by tree i), for i in 0..L-2.
        self._signed_pubs: list[tuple[bytes, bytes]] = []
        if signed_pubs is None:
            # Fresh key: consume one upper-tree leaf per level to sign the child
            # public key below it (RFC 8554 sec 6.2). Done exactly ONCE, at gen.
            self._prime_signed_pubs()
        else:
            if len(signed_pubs) != levels - 1:
                raise ValueError("HSS signed_pubs count must be levels - 1")
            # Restored key: reuse the persisted signed public keys WITHOUT
            # re-signing, so reloading from disk never burns another upper-tree
            # one-time leaf. This is essential -- re-priming on every load would
            # exhaust the upper tree after a handful of reloads.
            self._signed_pubs = list(signed_pubs)

    def _prime_signed_pubs(self) -> None:
        self._signed_pubs = []
        for i in range(self._levels - 1):
            child_pub = self._trees[i + 1].public_key().to_bytes()
            sig = self._trees[i].sign(child_pub)
            self._signed_pubs.append((child_pub, sig))

    def public_key(self) -> HssPublicKey:
        return HssPublicKey(self._levels, self._trees[0].public_key())

    def remaining(self) -> int:
        # Bound by the product of each tree's remaining capacity, conservatively
        # reported as the bottom tree's remaining signatures for the current
        # configuration (regeneration of upper trees is supported on exhaustion).
        total = 1
        for tree in self._trees:
            total *= tree.remaining()
        return total

    def _regenerate_bottom(self) -> None:
        """Advance exhausted lower trees (RFC Algorithm 8 step 1)."""
        d = self._levels
        while self._trees[d - 1].remaining() == 0:
            d -= 1
            if d == 0:
                raise RuntimeError("HSS private key is exhausted")
        while d < self._levels:
            new_tree = generate_lms_key(lms_type=self._lms_type, lmots_type=self._lmots_type)
            self._trees[d] = new_tree
            child_pub = new_tree.public_key().to_bytes()
            sig = self._trees[d - 1].sign(child_pub)
            self._signed_pubs[d - 1] = (child_pub, sig)
            d += 1

    def sign(self, message: bytes) -> bytes:
        if self._levels == 1:
            return _u32(0) + self._trees[0].sign(message)
        if self._trees[self._levels - 1].remaining() == 0:
            self._regenerate_bottom()
        body = bytearray()
        for child_pub, sig in self._signed_pubs:
            body += sig + child_pub
        final_sig = self._trees[self._levels - 1].sign(message)
        return _u32(self._levels - 1) + bytes(body) + final_sig

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": "hss",
            "levels": self._levels,
            "lms_type": self._lms_type.type_code,
            "lmots_type": self._lmots_type.type_code,
            "trees": [tree.to_dict() for tree in self._trees],
            # Persist the upper-tree signatures over the child public keys so a
            # restored key reuses them instead of re-signing (which would consume
            # another upper-tree one-time leaf on every reload).
            "signed_pubs": [[_b64e(pub), _b64e(sig)] for pub, sig in self._signed_pubs],
        }

    @classmethod
    def from_dict(cls, d: dict[str, object]) -> HssPrivateKey:
        if d.get("kind") != "hss":
            raise ValueError("not an HSS private key dict")
        levels = int(_as_int(d["levels"]))
        lms_type = _lms_params(int(_as_int(d["lms_type"])))
        lmots_type = _lmots_params(int(_as_int(d["lmots_type"])))
        raw_trees = d["trees"]
        if not isinstance(raw_trees, list):
            raise ValueError("HSS 'trees' must be a list")
        trees = [LmsPrivateKey.from_dict(_as_dict(t)) for t in raw_trees]
        signed_pubs: list[tuple[bytes, bytes]] | None = None
        raw_signed = d.get("signed_pubs")
        if isinstance(raw_signed, list):
            signed_pubs = []
            for pair in raw_signed:
                if not isinstance(pair, list) or len(pair) != 2:
                    raise ValueError("HSS signed_pubs entries must be [pub, sig] pairs")
                signed_pubs.append((_b64d(_as_str(pair[0])), _b64d(_as_str(pair[1]))))
        return cls(levels, trees, lms_type, lmots_type, signed_pubs)


# --- Typed-cast helpers for JSON deserialisation --------------------------


def _as_int(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"expected an int, got {type(value).__name__}")
    return value


def _as_str(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError(f"expected a str, got {type(value).__name__}")
    return value


def _as_dict(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"expected a dict, got {type(value).__name__}")
    return value


# --- Key generation -------------------------------------------------------


def generate_lms_key(
    *,
    lms_type: _LmsParams = LMS_SHA256_M32_H10,
    lmots_type: _LmotsParams = LMOTS_SHA256_N32_W8,
    identifier: bytes | None = None,
    seed: bytes | None = None,
) -> LmsPrivateKey:
    """Generate a fresh stateful LMS private key.

    Building the Merkle tree is deferred until the first ``sign``/``public_key``
    call, so generation itself is cheap; the cost is paid on first use. Use H5
    in tests (32 leaves) -- larger heights build exponentially many leaves.
    """
    chosen_id = identifier if identifier is not None else os.urandom(16)
    chosen_seed = seed if seed is not None else os.urandom(lms_type.m)
    return LmsPrivateKey(lms_type, lmots_type, chosen_id, chosen_seed, 0)


def generate_hss_key(
    levels: int = 2,
    *,
    lms_type: _LmsParams = LMS_SHA256_M32_H5,
    lmots_type: _LmotsParams = LMOTS_SHA256_N32_W8,
) -> HssPrivateKey:
    """Generate a fresh stateful HSS private key with ``levels`` LMS trees."""
    if levels < 1:
        raise ValueError("HSS requires at least one level")
    trees = [generate_lms_key(lms_type=lms_type, lmots_type=lmots_type) for _ in range(levels)]
    return HssPrivateKey(levels, trees, lms_type, lmots_type)
