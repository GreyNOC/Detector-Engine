from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from greynoc_detector_engine.analysis.crypto_inventory import (
    assess_inventory,
    build_asset,
    build_posture_summary,
    load_inventory,
    normalize_algorithm,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("RSA 2048", "RSA-2048"),
        ("rsaEncryption", "RSA-2048"),
        ("RSA-2048 (key exchange)", "RSA-2048-KEX"),
        ("ECDSA P-256", "ECDSA-P256"),
        ("prime256v1", "ECDSA-P256"),
        ("secp256r1", "ECDSA-P256"),
        ("ECDH P-256", "ECDH-P256"),
        ("X25519", "X25519"),
        ("curve25519", "X25519"),
        ("AES-256-GCM", "AES-256"),
        ("AES256", "AES-256"),
        ("ML-KEM-768", "ML-KEM-768"),
        ("Kyber768", "ML-KEM-768"),
        ("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "ECDH-P256"),
        ("Frobnicate-9000", None),
        ("", None),
    ],
)
def test_normalize_algorithm(raw: str, expected: str | None) -> None:
    assert normalize_algorithm(raw) == expected


def test_rsa_with_larger_modulus_maps_to_nearest_record() -> None:
    assert normalize_algorithm("RSA 3072") == "RSA-3072"
    assert normalize_algorithm("RSA-4096") == "RSA-4096"


def test_build_asset_unrecognized_falls_back() -> None:
    asset = build_asset({"name": "weird thing", "algorithm": "Frobnicate-9000"})
    assert asset.algorithm is None
    assert asset.identifier == "weird thing"
    assert asset.quantum_vulnerable is False


def test_build_asset_carries_parameter_set() -> None:
    asset = build_asset({"name": "api cert", "algorithm": "RSA 2048", "parameter_set": "n=2048"})
    assert asset.algorithm == "RSA-2048"
    assert asset.parameter_set == "n=2048"


def _mixed_inventory() -> list[dict[str, Any]]:
    return [
        {
            "name": "TLS cert for api.example.com",
            "algorithm": "RSA 2048",
            "kind": "certificate",
            "location": "api.example.com:443",
        },
        {
            "name": "VPN key exchange",
            "algorithm": "ECDH P-256",
            "kind": "protocol",
            "location": "vpn-gw",
            "data_shelf_life_years": 12,
        },
        {
            "name": "disk encryption",
            "algorithm": "AES-256-GCM",
            "kind": "algorithm",
        },
        {
            "name": "pq kem",
            "algorithm": "Kyber768",
            "kind": "algorithm",
        },
        {
            "name": "mystery",
            "algorithm": "Frobnicate-9000",
        },
    ]


def test_posture_summary_over_mixed_inventory() -> None:
    assets = [build_asset(entry) for entry in _mixed_inventory()]
    summary = build_posture_summary(assets)

    # RSA-2048 cert and ECDH P-256 are Shor-broken.
    assert summary.quantum_vulnerable == 2
    assert summary.unrecognized == 1
    # Quantum-safe must include the ML-KEM and the AES asset.
    assert summary.quantum_safe == 2
    safe_algos = {a.algorithm for a in assets if a.algorithm and not a.quantum_vulnerable}
    assert "ML-KEM-768" in safe_algos
    assert "AES-256" in safe_algos
    assert summary.harvest_now_decrypt_later >= 1
    assert 0.0 <= summary.readiness_score <= 1.0


def test_assess_inventory_produces_mosca_for_hndl_asset() -> None:
    assets, summary, mosca = assess_inventory(
        _mixed_inventory(),
        crqc_years=10.0,
        default_shelf_life_years=5.0,
        default_migration_years=3.0,
    )
    assert len(assets) == 5
    assert summary.harvest_now_decrypt_later >= 1
    assert mosca, "expected at least one Mosca assessment for an HNDL asset"

    # The VPN ECDH key exchange has a 12y shelf-life override -> already at risk.
    vpn = next(a for a in assets if a.location == "vpn-gw")
    key = vpn.identifier or vpn.location or ""
    assert key in mosca
    assert mosca[key].data_shelf_life_years == 12.0
    assert mosca[key].at_risk is True


def test_empty_inventory_readiness_is_one() -> None:
    _assets, summary, mosca = assess_inventory([])
    assert summary.total_assets == 0
    assert summary.readiness_score == 1.0
    assert mosca == {}


def test_load_inventory_yaml(tmp_path: Path) -> None:
    inventory = tmp_path / "inventory.yaml"
    inventory.write_text(
        "\n".join(
            [
                "assets:",
                "  - name: api cert",
                "    algorithm: RSA 2048",
                "    kind: certificate",
                "  - name: pq kem",
                "    algorithm: ML-KEM-768",
            ]
        ),
        encoding="utf-8",
    )
    entries = load_inventory(inventory)
    assert len(entries) == 2
    assets, summary, _mosca = assess_inventory(entries)
    assert summary.total_assets == 2
    assert any(a.algorithm == "RSA-2048" for a in assets)


def test_load_inventory_json_top_level_list(tmp_path: Path) -> None:
    inventory = tmp_path / "inventory.json"
    inventory.write_text(
        json.dumps([{"name": "c", "algorithm": "AES-256-GCM"}]),
        encoding="utf-8",
    )
    entries = load_inventory(inventory)
    assert entries == [{"name": "c", "algorithm": "AES-256-GCM"}]


def test_load_inventory_rejects_non_list(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("just a string", encoding="utf-8")
    with pytest.raises(ValueError, match="must be a list"):
        load_inventory(bad)
