"""Ingest a crypto inventory and assess its post-quantum posture.

This is the glass-box scanner side of the PQC layer: it takes a declared
cryptographic inventory (TLS certificates, key-exchange suites, symmetric
ciphers, library defaults, ...) and turns each entry into a recognized
:class:`~greynoc_detector_engine.models.crypto.CryptoAsset`, then aggregates
the whole inventory into a :class:`~greynoc_detector_engine.models.crypto.
CryptoPostureSummary` and runs Mosca's harvest-now-decrypt-later inequality
over every confidentiality / HNDL asset.

The hard part of real inventories is *normalization*: a certificate's signature
algorithm shows up as ``rsaEncryption``, ``RSA 2048``, ``RSA-2048 (key
exchange)``, ``prime256v1``, ``secp256r1``, ``ECDSA P-256`` -- all of which must
be resolved to one canonical registry name before the algorithm facts apply.
:func:`normalize_algorithm` does that best-effort mapping and falls back to the
registry's own alias lookup, then to ``None`` for genuinely unknown strings.

Everything here is offline arithmetic and string handling -- no model, no
network. Algorithm facts come from
:mod:`greynoc_detector_engine.crypto.algorithms` via ``CryptoAsset.
from_algorithm``; the Mosca calculation is delegated to
:func:`greynoc_detector_engine.analysis.mosca.assess_mosca` so the inequality
lives in exactly one place.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

from greynoc_detector_engine.analysis.mosca import assess_mosca
from greynoc_detector_engine.crypto import algorithms
from greynoc_detector_engine.models.crypto import (
    CryptoAsset,
    CryptoAssetKind,
    CryptoPostureSummary,
    MoscaAssessment,
)

# Default planning horizons (years). A conservative CRQC estimate plus a typical
# enterprise migration window; callers override per inventory / per asset.
DEFAULT_CRQC_YEARS = 10.0
DEFAULT_SHELF_LIFE_YEARS = 5.0
DEFAULT_MIGRATION_YEARS = 3.0


# ---------------------------------------------------------------------------
# Algorithm-string normalization
# ---------------------------------------------------------------------------

# Explicit "key exchange / key transport / key agreement" markers that turn an
# RSA signature record into the RSA key-establishment (HNDL) record.
_KEX_MARKERS = ("key exchange", "key-exchange", "key transport", "key agreement", "kex")

# Direct canonical mappings, keyed by a normalized (lower, separator-collapsed)
# form of the raw string. Checked before the heuristic passes below.
_DIRECT: dict[str, str] = {
    "rsaencryption": "RSA-2048",
    "rsa": "RSA-2048",
    "ecdsap256": "ECDSA-P256",
    "ecdsap384": "ECDSA-P384",
    "ecdhp256": "ECDH-P256",
    "ecdhp384": "ECDH-P384",
    "prime256v1": "ECDSA-P256",
    "secp256r1": "ECDSA-P256",
    "secp384r1": "ECDSA-P384",
    "x25519": "X25519",
    "curve25519": "X25519",
    "ed25519": "Ed25519",
    "eddsa": "Ed25519",
    "aes256gcm": "AES-256",
    "aes256": "AES-256",
    "aes256cbc": "AES-256",
    "aes128gcm": "AES-128",
    "aes128": "AES-128",
    "aes192": "AES-192",
    "3des": "3DES",
    "tripledes": "3DES",
    "mlkem512": "ML-KEM-512",
    "mlkem768": "ML-KEM-768",
    "mlkem1024": "ML-KEM-1024",
    "kyber512": "ML-KEM-512",
    "kyber768": "ML-KEM-768",
    "kyber1024": "ML-KEM-1024",
    "mldsa44": "ML-DSA-44",
    "mldsa65": "ML-DSA-65",
    "mldsa87": "ML-DSA-87",
    "dilithium2": "ML-DSA-44",
    "dilithium3": "ML-DSA-65",
    "dilithium5": "ML-DSA-87",
}

# RSA with an explicit modulus size -> the closest registered RSA record.
_RSA_SIZE_RE = re.compile(r"rsa[^0-9]*([0-9]{3,5})")


def _collapse(raw: str) -> str:
    """Lowercase and strip all non-alphanumerics for direct-table lookup."""
    return re.sub(r"[^a-z0-9]+", "", raw.casefold())


def _rsa_record_for_bits(bits: int) -> str:
    if bits <= 2048:
        return "RSA-2048"
    if bits <= 3072:
        return "RSA-3072"
    return "RSA-4096"


def normalize_algorithm(raw: str) -> str | None:
    """Map a real-world algorithm string to a canonical registry name.

    Handles the common shapes inventories emit (``RSA 2048``, ``rsaEncryption``,
    ``ECDSA P-256``, ``prime256v1``, ``X25519``, ``AES-256-GCM``, ``Kyber768``,
    ``TLS_...`` cipher suites, ...). Falls back to the registry's own alias
    lookup and then to ``None`` for genuinely unrecognized strings.
    """
    if not raw or not raw.strip():
        return None

    text = raw.strip()
    lowered = text.casefold()
    is_kex = any(marker in lowered for marker in _KEX_MARKERS)

    # 1. TLS cipher-suite names: best-effort extraction of the key-exchange and
    #    bulk cipher from the IANA-style token (e.g. TLS_ECDHE_RSA_WITH_AES_256_GCM).
    if lowered.startswith("tls"):
        suite = normalize_tls_suite(text)
        if suite is not None:
            return suite

    # 2. RSA with an explicit modulus size.
    rsa_match = _RSA_SIZE_RE.search(lowered)
    if rsa_match:
        rsa_name = _rsa_record_for_bits(int(rsa_match.group(1)))
        if is_kex:
            # Only RSA-2048 has a dedicated key-establishment record.
            return "RSA-2048-KEX"
        return rsa_name

    # 3. Direct collapsed-form table.
    collapsed = _collapse(text)
    if collapsed == "rsa" and is_kex:
        return "RSA-2048-KEX"
    direct = _DIRECT.get(collapsed)
    if direct is not None:
        return direct

    # 4. ECDH / ECDSA on a named NIST curve (e.g. "ECDH P-256", "ECDSA P-384").
    curve = _curve_token(lowered)
    if curve is not None:
        if "ecdh" in lowered or "ecdhe" in lowered:
            return f"ECDH-{curve}"
        if "ecdsa" in lowered or (not is_kex and "ecc" in lowered):
            return f"ECDSA-{curve}"

    # 5. Fall back to the registry's own case-insensitive alias resolution.
    record = algorithms.get(text)
    if record is not None:
        return record.name
    record = algorithms.get(collapsed)
    if record is not None:
        return record.name

    return None


_CURVE_RE = re.compile(r"p-?\s*(256|384|521|192)")


def _curve_token(lowered: str) -> str | None:
    """Extract a NIST curve label (P256/P384) from text like ``ECDH P-256``."""
    match = _CURVE_RE.search(lowered)
    if match:
        return f"P{match.group(1)}"
    if "prime256v1" in lowered or "secp256r1" in lowered:
        return "P256"
    if "secp384r1" in lowered:
        return "P384"
    return None


def normalize_tls_suite(raw: str) -> str | None:
    """Pull the most quantum-relevant primitive out of a TLS cipher-suite name.

    Inventories often list a whole suite (``TLS_ECDHE_RSA_WITH_AES_256_GCM_
    SHA384``). The key-establishment half is what carries harvest-now-decrypt-
    later risk, so it is preferred; otherwise the bulk symmetric cipher is
    returned. Returns ``None`` if nothing recognizable is present.
    """
    lowered = raw.casefold()
    if "ecdhe" in lowered or "ecdh" in lowered:
        curve = _curve_token(lowered) or "P256"
        return f"ECDH-{curve}"
    if "x25519" in lowered:
        return "X25519"
    if "_rsa" in lowered or lowered.startswith("tls_rsa"):
        return "RSA-2048-KEX"
    if "dhe" in lowered:
        return "DH-2048"
    if "aes_256" in lowered or "aes256" in lowered:
        return "AES-256"
    if "aes_128" in lowered or "aes128" in lowered:
        return "AES-128"
    return None


# ---------------------------------------------------------------------------
# Inventory entry -> CryptoAsset
# ---------------------------------------------------------------------------


def _kind_from_entry(entry: dict[str, Any]) -> CryptoAssetKind:
    raw_kind = entry.get("kind")
    if isinstance(raw_kind, str):
        try:
            return CryptoAssetKind(raw_kind.strip().casefold())
        except ValueError:
            pass
    return CryptoAssetKind.ALGORITHM


def build_asset(entry: dict[str, Any]) -> CryptoAsset:
    """Build a :class:`CryptoAsset` from one inventory entry dict.

    Recognizes ``name``, ``algorithm``, ``kind``, ``location``, ``parameter_set``
    and (for the Mosca pass) ``data_shelf_life_years``. The algorithm string is
    normalized first, then resolved through ``CryptoAsset.from_algorithm`` so the
    registry facts attach; unrecognized strings fall back to an unrecognized
    asset carrying the original label.
    """
    raw_algorithm = entry.get("algorithm") or entry.get("name") or ""
    name = entry.get("name")
    location = entry.get("location")
    parameter_set = entry.get("parameter_set")
    kind = _kind_from_entry(entry)
    identifier = name if isinstance(name, str) and name else None

    canonical = normalize_algorithm(str(raw_algorithm)) if raw_algorithm else None
    lookup = canonical if canonical is not None else str(raw_algorithm)

    asset = CryptoAsset.from_algorithm(
        lookup,
        identifier=identifier,
        kind=kind,
        location=location if isinstance(location, str) else None,
        source="crypto_inventory",
    )
    if isinstance(parameter_set, str) and parameter_set:
        asset.parameter_set = parameter_set
    return asset


# ---------------------------------------------------------------------------
# Posture aggregation
# ---------------------------------------------------------------------------


def build_posture_summary(assets: list[CryptoAsset]) -> CryptoPostureSummary:
    """Aggregate a list of assets into a :class:`CryptoPostureSummary`."""
    total = len(assets)
    vulnerable = sum(1 for a in assets if a.quantum_vulnerable)
    unrecognized = sum(1 for a in assets if a.algorithm is None)
    # Quantum-safe == recognized and not Shor-broken.
    safe = sum(1 for a in assets if a.algorithm is not None and not a.quantum_vulnerable)
    hndl = sum(1 for a in assets if a.harvest_now_decrypt_later)

    by_family: Counter[str] = Counter()
    by_threat: Counter[str] = Counter()
    for asset in assets:
        if asset.family is not None:
            by_family[asset.family.value] += 1
        if asset.quantum_threat is not None:
            by_threat[asset.quantum_threat.value] += 1
        else:
            by_threat["unrecognized"] += 1

    readiness = 1.0 if total == 0 else round(safe / total, 4)

    findings: list[str] = []
    if hndl:
        findings.append(
            f"{hndl} asset{'s' if hndl != 1 else ''} are harvest-now-decrypt-later "
            "exposed: their traffic can be recorded today and decrypted once a CRQC exists."
        )
    if vulnerable:
        findings.append(
            f"{vulnerable} of {total} asset{'s' if total != 1 else ''} use Shor-broken "
            "public-key cryptography and must migrate to a NIST PQC algorithm."
        )
    if unrecognized:
        findings.append(
            f"{unrecognized} asset{'s' if unrecognized != 1 else ''} could not be matched to "
            "the algorithm registry and need manual review."
        )
    if total and safe == total:
        findings.append("All recognized assets are already quantum-safe.")
    if not findings:
        findings.append("No assets in inventory.")

    return CryptoPostureSummary(
        total_assets=total,
        quantum_vulnerable=vulnerable,
        quantum_safe=safe,
        unrecognized=unrecognized,
        harvest_now_decrypt_later=hndl,
        by_family=dict(by_family),
        by_threat=dict(by_threat),
        readiness_score=readiness,
        findings=findings,
    )


def _shelf_life_for(entry: dict[str, Any], default: float) -> float:
    raw = entry.get("data_shelf_life_years")
    if isinstance(raw, int | float) and not isinstance(raw, bool):
        value = float(raw)
        if value >= 0:
            return value
    return default


def _mosca_key(asset: CryptoAsset) -> str:
    return asset.identifier or asset.location or asset.algorithm or "unknown"


def assess_inventory(
    entries: list[dict[str, Any]],
    *,
    crqc_years: float = DEFAULT_CRQC_YEARS,
    default_shelf_life_years: float = DEFAULT_SHELF_LIFE_YEARS,
    default_migration_years: float = DEFAULT_MIGRATION_YEARS,
) -> tuple[list[CryptoAsset], CryptoPostureSummary, dict[str, MoscaAssessment]]:
    """Assess a full inventory: assets, posture summary, and per-asset Mosca.

    A :class:`MoscaAssessment` is produced for every harvest-now-decrypt-later
    asset (a confidentiality primitive that is Shor-broken), using the entry's
    own ``data_shelf_life_years`` when present or ``default_shelf_life_years``
    otherwise. The Mosca dict is keyed by ``asset.identifier`` (falling back to
    ``location`` / ``algorithm``).
    """
    assets: list[CryptoAsset] = []
    mosca: dict[str, MoscaAssessment] = {}

    for entry in entries:
        asset = build_asset(entry)
        assets.append(asset)
        if asset.harvest_now_decrypt_later:
            shelf_life = _shelf_life_for(entry, default_shelf_life_years)
            mosca[_mosca_key(asset)] = assess_mosca(
                data_shelf_life_years=shelf_life,
                migration_years=default_migration_years,
                crqc_years=crqc_years,
            )

    summary = build_posture_summary(assets)
    return assets, summary, mosca


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def load_inventory(path: str | Path) -> list[dict[str, Any]]:
    """Read a YAML or JSON inventory file into a list of entry dicts.

    Accepts a top-level list of entries or a mapping with an ``"assets"`` key.
    JSON is a subset of YAML, so ``yaml.safe_load`` parses both. Raises
    :class:`ValueError` if the document is not a list or an ``{"assets": [...]}``
    mapping, or if any entry is not a mapping.
    """
    file_path = Path(path)
    text = file_path.read_text(encoding="utf-8")
    if file_path.suffix.casefold() == ".json":
        data: Any = json.loads(text)
    else:
        data = yaml.safe_load(text)

    if data is None:
        return []
    if isinstance(data, dict):
        data = data.get("assets", [])
    if not isinstance(data, list):
        raise ValueError(
            f"inventory at {file_path} must be a list or an {{'assets': [...]}} mapping"
        )

    entries: list[dict[str, Any]] = []
    for item in data:
        if not isinstance(item, dict):
            raise ValueError(f"inventory entry must be a mapping, got {type(item).__name__}")
        entries.append(item)
    return entries
