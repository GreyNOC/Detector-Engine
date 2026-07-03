from __future__ import annotations

import importlib.util
import json

import pytest

from greynoc_detector_engine.analysis.cbom import (
    assess_cbom,
    generate_cbom,
    parse_cbom,
    to_json,
)
from greynoc_detector_engine.models.cbom import Cbom
from greynoc_detector_engine.models.crypto import CryptoAsset, CryptoPostureSummary


def _has_inventory() -> bool:
    return importlib.util.find_spec("greynoc_detector_engine.analysis.crypto_inventory") is not None


def _assets() -> list[CryptoAsset]:
    return [
        CryptoAsset.from_algorithm("RSA-2048"),
        CryptoAsset.from_algorithm("ML-KEM-768"),
    ]


def test_generate_cbom_emits_cyclonedx_1_6() -> None:
    cbom = generate_cbom(_assets())
    assert isinstance(cbom, Cbom)
    assert cbom.bomFormat == "CycloneDX"
    assert cbom.specVersion == "1.6"
    assert cbom.serialNumber.startswith("urn:uuid:")
    assert cbom.serialNumber == cbom.serialNumber.lower()
    assert cbom.version == 1
    assert len(cbom.components) == 2


def test_to_json_round_trip_and_hyphenated_bom_ref() -> None:
    cbom = generate_cbom(_assets())
    j = to_json(cbom)
    d = json.loads(j)

    assert d["bomFormat"] == "CycloneDX"
    assert d["specVersion"] == "1.6"

    components = d["components"]
    assert len(components) == 2
    for component in components:
        # The hyphenated CycloneDX key must be present (not the python name).
        assert "bom-ref" in component
        assert "bom_ref" not in component
        assert component["type"] == "cryptographic-asset"
        assert component["cryptoProperties"]["assetType"] == "algorithm"


def test_nist_quantum_security_level_matches_registry() -> None:
    cbom = generate_cbom(_assets())
    d = json.loads(to_json(cbom))
    by_param = {
        c["cryptoProperties"]["algorithmProperties"]["parameterSetIdentifier"]: c
        for c in d["components"]
    }

    mlkem = by_param["ML-KEM-768"]
    algo = mlkem["cryptoProperties"]["algorithmProperties"]
    # ML-KEM-768 is NIST category 3, primitive kem.
    assert algo["nistQuantumSecurityLevel"] == 3
    assert algo["primitive"] == "kem"

    rsa = by_param["RSA-2048"]["cryptoProperties"]["algorithmProperties"]
    assert rsa["primitive"] == "signature"


def test_parse_cbom_recovers_assets_and_reenriches() -> None:
    cbom = generate_cbom(_assets())
    d = json.loads(to_json(cbom))

    assets = parse_cbom(d)
    assert len(assets) >= 2

    by_name = {a.algorithm: a for a in assets}
    assert "ML-KEM-768" in by_name
    # Re-recognised from the registry: ML-KEM-768 is NOT quantum-vulnerable.
    assert by_name["ML-KEM-768"].quantum_vulnerable is False

    assert "RSA-2048" in by_name
    assert by_name["RSA-2048"].quantum_vulnerable is True


def test_parse_cbom_accepts_json_string() -> None:
    cbom = generate_cbom(_assets())
    j = to_json(cbom)
    assets = parse_cbom(j)
    assert len(assets) == 2


@pytest.mark.skipif(
    not _has_inventory(),
    reason="analysis.crypto_inventory.build_posture_summary not available",
)
def test_assess_cbom_returns_posture_summary() -> None:
    cbom = generate_cbom(_assets())
    summary = assess_cbom(cbom)
    assert isinstance(summary, CryptoPostureSummary)
    assert summary.quantum_vulnerable >= 1
