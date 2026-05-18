from __future__ import annotations

from typing import Any

from greynoc_detection_engine.ingest.base import BaseIngestor
from greynoc_detection_engine.models.source import SourceItem
from greynoc_detection_engine.normalize.normalizer import SourceItemNormalizer
from greynoc_detection_engine.utils.time import parse_datetime


class GitHubIngestor(BaseIngestor[SourceItem]):
    """Collect GitHub metadata only; never clone, download, or execute repository code."""

    def ingest(self) -> list[SourceItem]:
        payload = self.load_json_payload()
        records = payload if isinstance(payload, list) else [payload]
        return [self._normalize_record(record) for record in records if isinstance(record, dict)]

    def _normalize_record(self, record: dict[str, Any]) -> SourceItem:
        name = record.get("full_name") or record.get("name") or self.source_config.name
        description = record.get("description") or ""
        content = " ".join(
            str(part)
            for part in (
                name,
                description,
                record.get("topics", []),
                record.get("default_branch", ""),
            )
            if part
        )
        metadata = {
            "stars": record.get("stargazers_count"),
            "forks": record.get("forks_count"),
            "open_issues": record.get("open_issues_count"),
            "pushed_at": record.get("pushed_at"),
            "metadata_only": True,
        }
        return SourceItemNormalizer().normalize(
            self.source_config,
            title=str(name),
            content=content,
            url=record.get("html_url") or self.source_config.url,
            published_at=parse_datetime(record.get("created_at")),
            metadata=metadata,
        )
