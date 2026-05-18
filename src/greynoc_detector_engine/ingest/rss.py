from __future__ import annotations

from email.utils import parsedate_to_datetime

import feedparser

from greynoc_detector_engine.ingest.base import BaseIngestor
from greynoc_detector_engine.models.source import SourceItem
from greynoc_detector_engine.normalize.normalizer import SourceItemNormalizer
from greynoc_detector_engine.utils.time import ensure_utc


class RSSIngestor(BaseIngestor[SourceItem]):
    def ingest(self) -> list[SourceItem]:
        payload = self.load_text_payload()
        parsed = feedparser.parse(payload)
        normalizer = SourceItemNormalizer()
        items: list[SourceItem] = []
        for entry in parsed.entries:
            published_at = None
            if entry.get("published"):
                published_at = ensure_utc(parsedate_to_datetime(entry.published))
            content = entry.get("summary") or entry.get("description") or entry.get("title") or ""
            items.append(
                normalizer.normalize(
                    self.source_config,
                    title=entry.get("title", "Untitled source item"),
                    content=content,
                    url=entry.get("link"),
                    author=entry.get("author"),
                    published_at=published_at,
                    metadata={"feed": parsed.feed.get("title", self.source_config.name)},
                )
            )
        return items
