from __future__ import annotations

from pathlib import Path

from greynoc_detection_engine.config.settings import Settings
from greynoc_detection_engine.ingest.cve_ingestor import CVEIngestor
from greynoc_detection_engine.models.source import SourceCategory, SourceConfig, SourceType


def test_cve_ingestor_normalizes_nvd_fixture(tmp_path: Path) -> None:
    source = SourceConfig(
        id="test-cve",
        name="Test CVE",
        category=SourceCategory.CVE,
        type=SourceType.CVE_JSON,
        url="https://example.test/cve",
    )
    records = CVEIngestor(
        source,
        Settings(database_path=tmp_path / "test.sqlite"),
        fixture_path=Path("tests/fixtures/cve_sample.json"),
    ).ingest()

    assert len(records) == 1
    record = records[0]
    assert record.cve_id == "CVE-2026-12345"
    assert record.cvss_score == 9.8
    assert record.cwe == ["CWE-78"]
    assert "examplecorp:gateway" in record.affected_products
    assert record.exploit_references
    assert record.source_references[0].content_hash
