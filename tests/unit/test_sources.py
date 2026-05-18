from __future__ import annotations

from pathlib import Path

from greynoc_detection_engine.config.settings import SourceRegistry
from greynoc_detection_engine.models.source import SourceType


def test_source_registry_loads_yaml() -> None:
    registry = SourceRegistry.from_yaml(Path("src/greynoc_detection_engine/config/sources.yaml"))
    assert registry.enabled()
    assert registry.by_type(SourceType.CVE_JSON)[0].source_id == "nvd-cve-json"
    assert registry.metadata["policy"]["defensive_only"] is True
