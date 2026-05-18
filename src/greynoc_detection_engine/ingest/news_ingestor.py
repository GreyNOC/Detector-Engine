from __future__ import annotations

from greynoc_detection_engine.ingest.rss_ingestor import RSSIngestor


class NewsIngestor(RSSIngestor):
    """RSS-backed news ingestor with weak-signal extraction in downstream normalizers."""
