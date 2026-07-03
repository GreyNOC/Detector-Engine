from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from greynoc_detector_engine.api.main import create_app


@pytest.fixture
def client() -> Iterator[TestClient]:
    with TestClient(create_app()) as test_client:
        yield test_client


_INVENTORY = {
    "assets": [
        {"name": "api-cert", "algorithm": "RSA-2048", "kind": "certificate"},
        {"name": "vpn-kex", "algorithm": "ECDH P-256"},
        {"name": "future-kem", "algorithm": "ML-KEM-768"},
    ]
}


def test_crypto_posture_reports_pq_ready(client: TestClient) -> None:
    body = client.get("/crypto/posture").json()
    assert body["ready"] is True
    assert body["lms_signing"] is True
    assert body["pq_non_repudiation"] is True


def test_crypto_algorithms_and_timeline(client: TestClient) -> None:
    cnsa = client.get("/crypto/algorithms", params={"cnsa": "true"}).json()
    assert {row["name"] for row in cnsa} >= {"ML-KEM-1024", "ML-DSA-87"}
    timeline = client.get("/crypto/timeline").json()
    assert timeline["nsm10_endpoint_year"] == 2035


def test_crypto_selftest_endpoint(client: TestClient) -> None:
    report = client.get("/crypto/selftest").json()
    assert report["failed"] == 0


def test_quantum_scan_flags_harvest_now_decrypt_later(client: TestClient) -> None:
    body = client.post(
        "/quantum/scan",
        json={
            "text": "TLS RSA key exchange flaw; harvest now decrypt later",
            "products": ["OpenSSL"],
        },
    ).json()
    assert body["risk_level"] == "critical"
    assert body["harvest_now_decrypt_later"] is True


def test_quantum_mosca_endpoint(client: TestClient) -> None:
    body = client.post(
        "/quantum/mosca",
        json={"data_shelf_life_years": 10, "migration_years": 7, "crqc_years": 8},
    ).json()
    assert body["at_risk"] is True


def test_quantum_inventory_plan_and_cbom_endpoints(client: TestClient) -> None:
    inv = client.post("/quantum/inventory", json=_INVENTORY).json()
    assert inv["summary"]["total_assets"] == 3
    assert inv["summary"]["quantum_vulnerable"] >= 2

    plan = client.post("/quantum/plan", json=_INVENTORY).json()
    assert plan["total_assets"] == 3
    assert plan["immediate"] + plan["high"] >= 1

    cbom = client.post("/quantum/cbom", json=_INVENTORY).json()
    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["specVersion"] == "1.6"
    assert any("bom-ref" in component for component in cbom["components"])


def test_quantum_scan_rejects_unknown_fields(client: TestClient) -> None:
    # extra="forbid" on the request model -> 422 on unexpected keys.
    response = client.post("/quantum/scan", json={"text": "x", "bogus": 1})
    assert response.status_code == 422
