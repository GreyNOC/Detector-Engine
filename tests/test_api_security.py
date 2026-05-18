from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from greynoc_detector_engine.api.dependencies import require_api_key, resolve_fixture_path
from greynoc_detector_engine.config.settings import Settings


@pytest.fixture()
def settings(tmp_path: Path) -> Settings:
    fixture_root = tmp_path / "fixtures"
    fixture_root.mkdir()
    return Settings(api_key="secret", fixture_root=fixture_root)


def _security_app(settings: Settings) -> FastAPI:
    app = FastAPI()

    def get_test_settings() -> Settings:
        return settings

    app.dependency_overrides = {}

    @app.post("/protected", dependencies=[Depends(require_api_key)])
    def protected() -> dict[str, str]:
        return {"status": "ok"}

    from greynoc_detector_engine.api import dependencies as deps

    app.dependency_overrides[deps.get_app_settings] = get_test_settings
    return app


def test_require_api_key_accepts_valid_key(settings: Settings) -> None:
    client = TestClient(_security_app(settings))
    response = client.post("/protected", headers={"x-greynoc-api-key": "secret"})
    assert response.status_code == 200


def test_require_api_key_rejects_missing_key(settings: Settings) -> None:
    client = TestClient(_security_app(settings))
    response = client.post("/protected")
    assert response.status_code == 401


def test_resolve_fixture_path_allows_files_under_fixture_root(settings: Settings) -> None:
    fixture = settings.fixture_root / "cve.json"
    fixture.write_text("{}", encoding="utf-8")

    resolved = resolve_fixture_path("cve.json", settings)

    assert resolved == fixture.resolve()


def test_resolve_fixture_path_rejects_path_traversal(settings: Settings, tmp_path: Path) -> None:
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")

    with pytest.raises(Exception):
        resolve_fixture_path(str(outside), settings)
