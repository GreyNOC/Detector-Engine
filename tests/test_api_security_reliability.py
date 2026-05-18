from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from greynoc_detector_engine.api.job_locks import single_running_job
from greynoc_detector_engine.api.main import create_app
from greynoc_detector_engine.config.settings import get_settings
from greynoc_detector_engine.storage.sqlite import SQLiteStorage


@pytest.fixture(autouse=True)
def clear_settings_cache() -> None:
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _configure_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, env: str) -> None:
    monkeypatch.setenv("GREYNOC_ENV", env)
    monkeypatch.setenv("GREYNOC_DATABASE_PATH", str(tmp_path / "api.sqlite"))
    monkeypatch.setenv("GREYNOC_FIXTURE_ROOT", str(tmp_path))
    monkeypatch.delenv("GREYNOC_API_KEY", raising=False)
    get_settings.cache_clear()


def test_mutating_route_requires_api_key_outside_local(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _configure_env(monkeypatch, tmp_path, env="production")

    with TestClient(create_app()) as client:
        response = client.post("/correlate")

    assert response.status_code == 401
    assert "GREYNOC_API_KEY is required" in response.json()["detail"]


def test_mutating_route_accepts_valid_api_key_outside_local(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _configure_env(monkeypatch, tmp_path, env="production")
    monkeypatch.setenv("GREYNOC_API_KEY", "test-key")
    get_settings.cache_clear()

    with TestClient(create_app()) as client:
        response = client.post("/correlate", headers={"x-greynoc-api-key": "test-key"})

    assert response.status_code == 200


def test_local_mutating_route_stays_open_without_api_key(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _configure_env(monkeypatch, tmp_path, env="test")

    with TestClient(create_app()) as client:
        response = client.post("/correlate")

    assert response.status_code == 200


def test_list_limit_is_capped_at_500(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _configure_env(monkeypatch, tmp_path, env="test")

    with TestClient(create_app()) as client:
        response = client.get("/threats?limit=501")

    assert response.status_code == 422


def test_storage_initializes_once_per_app_lifespan(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _configure_env(monkeypatch, tmp_path, env="test")
    calls: list[Path] = []
    original_initialize = SQLiteStorage.initialize

    def counted_initialize(self: SQLiteStorage) -> None:
        calls.append(self.path)
        original_initialize(self)

    monkeypatch.setattr(SQLiteStorage, "initialize", counted_initialize)

    with TestClient(create_app()) as client:
        assert client.get("/threats").status_code == 200
        assert client.get("/cves").status_code == 200

    assert calls == [tmp_path / "api.sqlite"]


def test_duplicate_job_lock_returns_conflict() -> None:
    with single_running_job("test:duplicate"):
        with pytest.raises(HTTPException) as exc_info:
            with single_running_job("test:duplicate"):
                pass

    assert exc_info.value.status_code == 409
    assert "Job already running" in str(exc_info.value.detail)
