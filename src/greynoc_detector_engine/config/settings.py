from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import SecretStr
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
    fetch_live: bool = False
    github_token: SecretStr | None = None
    log_level: str = "INFO"
    request_timeout_seconds: float = 20.0
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
