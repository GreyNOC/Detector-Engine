from __future__ import annotations

from pathlib import Path

from greynoc_detector_engine.analysis.correlation import CorrelationEngine
from greynoc_detector_engine.config.settings import Settings
from greynoc_detector_engine.ingest.cve import CVEIngestor
from greynoc_detector_engine.ingest.kev import KEVIngestor
from greynoc_detector_engine.models.source import SourceCategory, SourceConfig, SourceType
from greynoc_detector_engine.normalize.normalizer import SourceItemNormalizer


def test_correlation_links_cve_kev_and_source_items(tmp_path: Path) -> None:
    settings = Settings(database_path=tmp_path / "test.sqlite")
    cve_source = SourceConfig(
        id="test-cve",
        name="Test CVE",
        category=SourceCategory.CVE,
        type=SourceType.CVE_JSON,
    )
    kev_source = SourceConfig(
        id="test-kev",
        name="Test KEV",
        category=SourceCategory.KEV,
        type=SourceType.KEV_JSON,
    )
    blog_source = SourceConfig(
        id="test-blog",
        name="Test Blog",
        category=SourceCategory.SECURITY_RESEARCH_BLOG,
        type=SourceType.RSS,
    )
    cves = CVEIngestor(
        cve_source,
        settings,
        fixture_path=Path("data/fixtures/cve_sample.json"),
    ).ingest()
    kev = KEVIngestor(
        kev_source,
        settings,
        fixture_path=Path("data/fixtures/kev_sample.json"),
    ).ingest()
    item = SourceItemNormalizer().normalize(
        blog_source,
        title="RAG poisoning and CVE-2026-12345 exploitation in the wild",
        content="RAG poisoning report mentions ransomware and emergency patch language.",
    )

    report = CorrelationEngine().correlate(cves=cves, kev_entries=kev, source_items=[item])

    assert report.relationships
    assert report.threats[0].related_kev_entries == ["CVE-2026-12345"]
    assert report.threats[0].early_warning_score is not None
