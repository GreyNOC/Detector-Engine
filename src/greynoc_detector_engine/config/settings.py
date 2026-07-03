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
    allow_insecure_http: bool = False
    block_private_fetch_hosts: bool = True
    user_agent: str = "greynoc-detector-engine/0.1 defensive-research"
    # Shared secret for HMAC-SHA256 artifact signing (detections/STIX exports).
    # Quantum-resistant integrity baseline; public-key PQ signing uses the 'pq' extra.
    signing_hmac_key: SecretStr | None = None
    # On-disk keystore for managed signing keys (incl. stateful LMS/HSS state) and
    # the append-only, PQ-signed transparency log of published artifacts.
    keystore_path: Path = Path("data/keystore/greynoc_keystore.json")
    transparency_log_path: Path = Path("data/transparency/artifact_log.jsonl")
    # Managed keystore key that signs transparency-log checkpoints. Using one
    # persistent, pinnable key (rather than a throwaway key per checkpoint) gives
    # the log a stable well-known public key that verifiers pin to reject forged
    # signed tree heads (RFC 6962-style authenticity).
    transparency_log_key_id: str = "transparency-log"
    # Preferred public-key signing backend for new keys: "lms" (stdlib, always
    # available, post-quantum), "ml-dsa" (liboqs), or "ed25519" (classical).
    signing_algorithm: str = "lms"
    # Mosca-inequality planning defaults (years). crqc_estimate ~ Z; the engine's
    # own data shelf-life ~ X; an enterprise migration ~ Y. Override per scan.
    crqc_estimate_years: float = Field(default=10.0, ge=0)
    default_data_shelf_life_years: float = Field(default=10.0, ge=0)
    default_migration_years: float = Field(default=5.0, ge=0)


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
