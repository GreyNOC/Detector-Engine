from __future__ import annotations

from pathlib import Path

from greynoc_detection_engine.config.settings import Settings
from greynoc_detection_engine.ingest.kev_ingestor import KEVIngestor
from greynoc_detection_engine.models.source import SourceCategory, SourceConfig, SourceType


def test_kev_ingestor_normalizes_cisa_fixture(tmp_path: Path) -> None:
    source = SourceConfig(
        id="test-kev",
        name="Test KEV",
        category=SourceCategory.KEV,
        type=SourceType.KEV_JSON,
        url="https://example.test/kev",
    )
    records = KEVIngestor(
        source,
        Settings(database_path=tmp_path / "test.sqlite"),
        fixture_path=Path("tests/fixtures/kev_sample.json"),
    ).ingest()

    assert len(records) == 1
    record = records[0]
    assert record.cve_id == "CVE-2026-12345"
    assert record.vendor_project == "ExampleCorp"
    assert record.known_ransomware_campaign_use == "Known"
    assert record.source_references[0].source == "Test KEV"
