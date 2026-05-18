from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

from greynoc_detection_engine.models.source import SourceConfig


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="GREYNOC_",
        extra="ignore",
    )

    env: str = "local"
    database_path: Path = Path("data/threat_library/greynoc_detection_engine.sqlite")
    data_dir: Path = Path("data")
    sources_path: Path = Field(
        default_factory=lambda: Path(__file__).with_name("sources.yaml"),
    )
    fetch_live: bool = False
    github_token: SecretStr | None = None
    log_level: str = "INFO"
    request_timeout_seconds: float = 20.0
    user_agent: str = "GreyNOC-Detection-Engine/0.1 defensive-research"


class SourceRegistry:
    def __init__(self, sources: list[SourceConfig], metadata: dict[str, Any] | None = None) -> None:
        self.sources = sources
        self.metadata = metadata or {}

    @classmethod
    def from_yaml(cls, path: Path) -> SourceRegistry:
        with path.open("r", encoding="utf-8") as handle:
            payload = yaml.safe_load(handle) or {}
        sources = [SourceConfig.model_validate(item) for item in payload.get("sources", [])]
        metadata = {key: value for key, value in payload.items() if key != "sources"}
        return cls(sources=sources, metadata=metadata)

    def enabled(self) -> list[SourceConfig]:
        return [source for source in self.sources if source.enabled]

    def by_type(self, source_type: str) -> list[SourceConfig]:
        return [source for source in self.enabled() if source.type == source_type]

    def by_id(self, source_id: str) -> SourceConfig | None:
        return next((source for source in self.sources if source.source_id == source_id), None)


@lru_cache
def get_settings() -> Settings:
    return Settings()


def load_source_registry(path: Path | None = None) -> SourceRegistry:
    settings = get_settings()
    return SourceRegistry.from_yaml(path or settings.sources_path)
