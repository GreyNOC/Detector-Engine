from __future__ import annotations

from pathlib import Path

from greynoc_detector_engine.config.settings import load_scoring_config
from greynoc_detector_engine.config.source_registry import SourceRegistry
from greynoc_detector_engine.models.source import SourceType


def test_source_registry_loads_yaml() -> None:
    registry = SourceRegistry.from_yaml(Path("config/sources.yaml"))
    assert registry.enabled()
    assert registry.by_type(SourceType.CVE_JSON)[0].source_id == "nvd-cve-json"
    assert registry.by_type(SourceType.GITHUB_SEARCH)
    assert registry.metadata["policy"]["defensive_only"] is True


def test_scoring_config_loads_yaml() -> None:
    scoring = load_scoring_config(Path("config/scoring.yaml"))
    assert scoring["early_warning_weights"]["kev_presence"] == 16
