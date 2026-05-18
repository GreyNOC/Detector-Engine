from __future__ import annotations

from fastapi.testclient import TestClient

from greynoc_detection_engine.api.main import create_app


def test_api_health_endpoint() -> None:
    client = TestClient(create_app())
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
