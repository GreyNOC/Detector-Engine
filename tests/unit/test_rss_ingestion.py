from __future__ import annotations

from pathlib import Path

from greynoc_detector_engine.config.settings import Settings
from greynoc_detector_engine.ingest.rss import RSSIngestor
from greynoc_detector_engine.models.source import SourceCategory, SourceConfig, SourceType


def test_rss_ingestor_parses_fixture(tmp_path: Path) -> None:
    source = SourceConfig(
        id="test-rss",
        name="Test RSS",
        category=SourceCategory.RSS_FEED,
        type=SourceType.RSS,
        url="https://example.test/feed.xml",
    )
    items = RSSIngestor(
        source,
        Settings(database_path=tmp_path / "test.sqlite"),
        fixture_path=Path("data/fixtures/rss_sample.xml"),
    ).ingest()

    assert len(items) == 1
    assert "RAG poisoning" in items[0].title
    assert items[0].content_hash
