from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

from greynoc_detector_engine.config.source_registry import SourceRegistry


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="GREYNOC_",
        extra="ignore",
    )

    env: str = "local"
    database_path: Path = Path("data/threat_library/greynoc_detector_engine.sqlite")
    data_dir: Path = Path("data")
    sources_path: Path = Path("config/sources.yaml")
    scoring_path: Path = Path("config/scoring.yaml")
    attack_horizon_path: Path = Path("config/attack_horizon.yaml")
    fixture_root: Path = Path("data/fixtures")
    fetch_live: bool = False
    github_token: SecretStr | None = None
    api_key: SecretStr | None = None
    log_level: str = "INFO"
    request_timeout_seconds: float = 20.0
    http_retries: int = Field(default=2, ge=0, le=5)
    max_response_bytes: int = Field(default=5_000_000, ge=1024)
    allowed_fetch_hosts: list[str] = Field(default_factory=list)
    user_agent: str = "greynoc-detector-engine/0.1 defensive-research"


@lru_cache
def get_settings() -> Settings:
    return Settings()


def load_source_registry(path: Path | None = None) -> SourceRegistry:
    settings = get_settings()
    return SourceRegistry.from_yaml(path or settings.sources_path)


def load_scoring_config(path: Path | None = None) -> dict[str, Any]:
    settings = get_settings()
    config_path = path or settings.scoring_path
    with config_path.open("r", encoding="utf-8") as handle:
        payload = yaml.safe_load(handle) or {}
    return dict(payload)


def load_attack_horizon_config(path: Path | None = None) -> dict[str, Any]:
    settings = get_settings()
    config_path = path or settings.attack_horizon_path
    with config_path.open("r", encoding="utf-8") as handle:
        payload = yaml.safe_load(handle) or {}
    return dict(payload)
