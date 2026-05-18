from __future__ import annotations

from pathlib import Path

from greynoc_detector_engine.config.settings import Settings
from greynoc_detector_engine.ingest.epss import EPSSIngestor
from greynoc_detector_engine.ingest.ransomwatch import RansomwatchIngestor
from greynoc_detector_engine.ingest.threatfox import ThreatFoxIngestor
from greynoc_detector_engine.ingest.urlhaus import URLhausIngestor
from greynoc_detector_engine.models.source import (
    SourceCategory,
    SourceConfig,
    SourceType,
)


def _settings(tmp_path: Path) -> Settings:
    return Settings(database_path=tmp_path / "test.sqlite")


def test_epss_ingestor_reads_fixture(tmp_path: Path) -> None:
    cfg = SourceConfig(
        id="first-org-epss",
        name="EPSS",
        category=SourceCategory.EPSS,
        type=SourceType.EPSS_JSON,
    )
    scores = EPSSIngestor(
        cfg, _settings(tmp_path), fixture_path=Path("data/fixtures/epss_sample.json")
    ).ingest()
    assert len(scores) >= 1
    assert scores[0].epss <= 1.0
    assert scores[0].cve_id.startswith("CVE-")


def test_threatfox_ingestor_normalizes_iocs(tmp_path: Path) -> None:
    cfg = SourceConfig(
        id="abusech-threatfox",
        name="ThreatFox",
        category=SourceCategory.OSINT_IOC_FEED,
        type=SourceType.THREATFOX_JSON,
    )
    reps = ThreatFoxIngestor(
        cfg, _settings(tmp_path), fixture_path=Path("data/fixtures/threatfox_sample.json")
    ).ingest()
    assert reps
    assert all(r.confidence > 0 for r in reps)
    assert any("Cobalt Strike" in r.tags for r in reps)


def test_urlhaus_ingestor_normalizes(tmp_path: Path) -> None:
    cfg = SourceConfig(
        id="abusech-urlhaus",
        name="URLhaus",
        category=SourceCategory.OSINT_IOC_FEED,
        type=SourceType.URLHAUS_JSON,
    )
    reps = URLhausIngestor(
        cfg, _settings(tmp_path), fixture_path=Path("data/fixtures/urlhaus_sample.json")
    ).ingest()
    assert reps
    assert reps[0].verdict.value == "malicious"


def test_ransomwatch_ingestor_normalizes_actor(tmp_path: Path) -> None:
    cfg = SourceConfig(
        id="ransomwatch-public",
        name="Ransomwatch",
        category=SourceCategory.RANSOMWARE_LEAK_TRACKER,
        type=SourceType.RANSOMWATCH_JSON,
    )
    posts = RansomwatchIngestor(
        cfg, _settings(tmp_path), fixture_path=Path("data/fixtures/ransomwatch_sample.json")
    ).ingest()
    assert posts
    assert any(p.actor == "lockbit" for p in posts)
