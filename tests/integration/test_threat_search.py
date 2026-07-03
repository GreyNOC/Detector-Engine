from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from greynoc_detector_engine.api.main import create_app
from greynoc_detector_engine.cli.main import app
from greynoc_detector_engine.config.settings import Settings, get_settings
from greynoc_detector_engine.models.prediction import (
    AttackForecast,
    ConfidenceBand,
    ForecastHorizon,
)
from greynoc_detector_engine.models.scoring import ScoreResult, score_label
from greynoc_detector_engine.models.threat import ThreatRecord, ThreatSeverity
from greynoc_detector_engine.workers.jobs import build_storage


@pytest.fixture()
def isolated_settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Settings:
    monkeypatch.setenv("GREYNOC_DATABASE_PATH", str(tmp_path / "engine.sqlite"))
    monkeypatch.setenv("GREYNOC_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("GREYNOC_FIXTURE_ROOT", str(tmp_path))
    get_settings.cache_clear()
    settings = get_settings()
    yield settings
    get_settings.cache_clear()


def _seed_threats(settings: Settings) -> None:
    storage = build_storage(settings)
    storage.upsert_threat(
        _threat(
            "Edge gateway exploit chatter",
            probability=0.86,
            severity=ThreatSeverity.CRITICAL,
            cve="CVE-2026-10001",
            product="ExampleCorp EdgeGateway",
            actor="Volt Typhoon",
            sector="energy",
        )
    )
    storage.upsert_threat(
        _threat(
            "Identity provider advisory",
            probability=0.31,
            severity=ThreatSeverity.MEDIUM,
            cve="CVE-2026-20002",
            product="ExampleID",
            actor="Unknown",
            sector="finance",
        )
    )


def _threat(
    title: str,
    *,
    probability: float,
    severity: ThreatSeverity,
    cve: str,
    product: str,
    actor: str,
    sector: str,
) -> ThreatRecord:
    return ThreatRecord(
        title=title,
        summary=f"{actor} activity against {product}",
        category="vulnerability",
        affected_products=[product],
        related_cves=[cve],
        suspected_actors=[actor],
        sectors_at_risk=[sector],
        severity=severity,
        predictive_score=ScoreResult(
            score=probability * 100,
            label=score_label(probability * 100),
        ),
        attack_forecast=AttackForecast(
            attack_probability=probability,
            horizon=ForecastHorizon.IMMINENT,
            horizon_days_p50=3,
            horizon_days_p90=7,
            confidence=ConfidenceBand.HIGH,
        ),
    )


def test_api_threat_search_filters_and_summarizes(isolated_settings: Settings) -> None:
    _seed_threats(isolated_settings)

    with TestClient(create_app()) as client:
        response = client.get(
            "/threats/search",
            params={
                "query": "edgegateway",
                "actor": "volt",
                "min_probability": 0.8,
            },
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["count"] == 1
    assert payload["threats"][0]["title"] == "Edge gateway exploit chatter"
    assert payload["threats"][0]["affected_products"] == ["ExampleCorp EdgeGateway"]


def test_api_threats_list_accepts_cve_and_summary_filters(
    isolated_settings: Settings,
) -> None:
    _seed_threats(isolated_settings)

    with TestClient(create_app()) as client:
        response = client.get(
            "/threats",
            params={"cve": "cve-2026-10001", "summary": True, "sort": "title"},
        )

    assert response.status_code == 200
    payload = response.json()
    assert len(payload) == 1
    assert payload[0]["related_cves"] == ["CVE-2026-10001"]
    assert "summary" not in payload[0]


def test_api_threat_search_rejects_invalid_probability_window(
    isolated_settings: Settings,
) -> None:
    _seed_threats(isolated_settings)

    with TestClient(create_app()) as client:
        response = client.get(
            "/threats/search",
            params={"min_probability": 0.9, "max_probability": 0.2},
        )

    assert response.status_code == 422


def test_cli_threats_list_supports_search_filters(isolated_settings: Settings) -> None:
    _seed_threats(isolated_settings)
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "threats",
            "list",
            "--query",
            "edgegateway",
            "--min-probability",
            "0.8",
            "--summary",
            "--pretty",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert len(payload) == 1
    assert payload[0]["title"] == "Edge gateway exploit chatter"
