from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Generic, TypeVar

from greynoc_detector_engine.config.settings import Settings
from greynoc_detector_engine.models.source import SourceConfig
from greynoc_detector_engine.utils.http import DefensiveHttpClient

T = TypeVar("T")


class IngestSourceUnavailable(RuntimeError):
    pass


class BaseIngestor(ABC, Generic[T]):
    def __init__(
        self,
        source_config: SourceConfig,
        settings: Settings,
        *,
        fixture_path: Path | None = None,
    ) -> None:
        self.source_config = source_config
        self.settings = settings
        self.fixture_path = fixture_path
        self.http = DefensiveHttpClient(
            timeout_seconds=settings.request_timeout_seconds,
            user_agent=settings.user_agent,
        )

    @abstractmethod
    def ingest(self) -> list[T]:
        """Fetch and normalize source data."""

    def load_json_payload(self) -> Any:
        if self.fixture_path:
            with self.fixture_path.open("r", encoding="utf-8") as handle:
                return json.load(handle)

        if not self.settings.fetch_live:
            raise IngestSourceUnavailable(
                f"{self.source_config.source_id} requires a fixture or GREYNOC_FETCH_LIVE=true"
            )
        if not self.source_config.url:
            raise IngestSourceUnavailable(f"{self.source_config.source_id} has no configured URL")
        return self.http.get_json(self.source_config.url)

    def load_text_payload(self) -> str:
        if self.fixture_path:
            return self.fixture_path.read_text(encoding="utf-8")

        if not self.settings.fetch_live:
            raise IngestSourceUnavailable(
                f"{self.source_config.source_id} requires a fixture or GREYNOC_FETCH_LIVE=true"
            )
        if not self.source_config.url:
            raise IngestSourceUnavailable(f"{self.source_config.source_id} has no configured URL")
        return self.http.get_text(self.source_config.url)
