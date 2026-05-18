from __future__ import annotations

from pathlib import Path

from greynoc_detector_engine.catalog.threat_library import ThreatLibrary
from greynoc_detector_engine.models.threat import ThreatRecord
from greynoc_detector_engine.storage.sqlite import SQLiteStorage


def test_threat_library_create_update_and_deduplicate(tmp_path: Path) -> None:
    storage = SQLiteStorage(tmp_path / "library.sqlite")
    storage.initialize()
    library = ThreatLibrary(storage)
    threat = ThreatRecord(
        title="ExampleCorp Gateway CVE",
        summary="Initial record.",
        category="vulnerability",
        related_cves=["CVE-2026-12345"],
    )

    created = library.create(threat)
    updated = library.update(created, "Updated during triage.")
    duplicate = ThreatRecord(
        title="Duplicate title",
        summary="Duplicate signal.",
        category="vulnerability",
        related_cves=["CVE-2026-12345"],
    )
    merged = library.upsert(duplicate)

    assert updated.version == 2
    assert merged.threat_id == created.threat_id
    assert merged.version >= 2
    assert library.get(created.threat_id) is not None
