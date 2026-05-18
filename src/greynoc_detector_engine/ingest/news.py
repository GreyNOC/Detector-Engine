from __future__ import annotations

from greynoc_detector_engine.ingest.rss import RSSIngestor


class NewsIngestor(RSSIngestor):
    """RSS-backed news ingestor with weak-signal extraction in downstream normalizers."""
