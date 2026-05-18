from __future__ import annotations

import secrets
from pathlib import Path

from fastapi import Depends, HTTPException, Query, Request, status

from greynoc_detector_engine.config.settings import Settings, get_settings
from greynoc_detector_engine.storage.sqlite import SQLiteStorage

_LOCAL_ENVS = {"local", "dev", "test"}


def get_storage(request: Request) -> SQLiteStorage:
    storage = getattr(request.app.state, "storage", None)
    if isinstance(storage, SQLiteStorage):
        return storage

    settings = get_settings()
    fallback_storage = SQLiteStorage(settings.database_path)
    fallback_storage.initialize()
    return fallback_storage


def get_app_settings() -> Settings:
    return get_settings()


def require_api_key(
    request: Request,
    settings: Settings = Depends(get_app_settings),
) -> None:
    """Protect mutating API endpoints outside local/dev/test."""
    expected_secret = settings.api_key
    env_name = settings.env.strip().lower()
    if expected_secret is None and env_name in _LOCAL_ENVS:
        return

    if expected_secret is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="GREYNOC_API_KEY is required outside local/dev/test.",
        )

    expected = expected_secret.get_secret_value()
    provided = request.headers.get("x-greynoc-api-key")
    if not provided or not secrets.compare_digest(provided, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Valid x-greynoc-api-key header required.",
        )


def resolve_fixture_path(
    fixture: str | None = Query(default=None),
    settings: Settings = Depends(get_app_settings),
) -> Path | None:
    """Resolve fixture paths under the configured fixture root only."""
    if fixture is None:
        return None

    fixture_root = settings.fixture_root.resolve()
    candidate = Path(fixture)
    if not candidate.is_absolute():
        candidate = fixture_root / candidate
    resolved = candidate.resolve()

    if fixture_root != resolved and fixture_root not in resolved.parents:
        raise HTTPException(status_code=400, detail="Fixture path must stay under fixture_root.")
    if not resolved.is_file():
        raise HTTPException(status_code=400, detail="Fixture file not found.")
    return resolved
