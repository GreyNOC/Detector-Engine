from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from greynoc_detector_engine.models.source import SourceConfig

SOURCE_CATEGORY_ALIASES = {
    "government_advisories": "government_advisory",
    "vendor_advisories": "vendor_advisory",
    "security_research": "security_research_blog",
    "ai_security": "ai_security_research",
}


class SourceRegistry:
    def __init__(self, sources: list[SourceConfig], metadata: dict[str, Any] | None = None) -> None:
        self.sources = sources
        self.metadata = metadata or {}

    @classmethod
    def from_yaml(cls, path: Path) -> SourceRegistry:
        with path.open("r", encoding="utf-8") as handle:
            payload = yaml.safe_load(handle) or {}
        sources = [SourceConfig.model_validate(item) for item in _source_items(payload)]
        metadata = {key: value for key, value in payload.items() if key not in {"sources"}}
        return cls(sources=sources, metadata=metadata)

    def enabled(self) -> list[SourceConfig]:
        return [source for source in self.sources if source.enabled]

    def by_type(self, source_type: str) -> list[SourceConfig]:
        return [source for source in self.enabled() if source.type == source_type]

    def by_id(self, source_id: str) -> SourceConfig | None:
        return next((source for source in self.sources if source.source_id == source_id), None)


def _source_items(payload: dict[str, Any]) -> list[dict[str, Any]]:
    if isinstance(payload.get("sources"), list):
        return list(payload["sources"])

    flattened: list[dict[str, Any]] = []
    for section, category in SOURCE_CATEGORY_ALIASES.items():
        for item in payload.get(section, []) or []:
            source = dict(item)
            source.setdefault("category", category)
            flattened.append(source)
    github_monitoring = payload.get("github_monitoring") or {}
    if github_monitoring:
        flattened.append(
            {
                "id": "github-keyword-monitoring",
                "name": "GitHub Keyword Metadata Monitoring",
                "category": "github_repository",
                "type": "github_search",
                "url": "https://api.github.com/search/repositories",
                "enabled": True,
                "reliability": "medium",
                "tags": ["github", "metadata-only", "defensive-monitoring"],
                "metadata": github_monitoring,
            }
        )
    return flattened
