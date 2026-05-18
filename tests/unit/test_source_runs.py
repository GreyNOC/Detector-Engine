from __future__ import annotations

import pytest
from pydantic import ValidationError

from greynoc_detector_engine.models.source import SourceRun, SourceRunStatus
from greynoc_detector_engine.storage.sqlite import SQLiteStorage
from greynoc_detector_engine.utils.time import utc_now


def test_failed_source_run_requires_error_message() -> None:
    with pytest.raises(ValidationError):
        SourceRun(source_id="test-source", status=SourceRunStatus.FAILED)


def test_sqlite_storage_persists_structured_source_runs(tmp_path) -> None:
    storage = SQLiteStorage(tmp_path / "detector.db")
    storage.initialize()

    started_at = utc_now()
    ended_at = utc_now()
    stored = storage.record_source_run(
        SourceRun(
            source_id="cisa-kev",
            status=SourceRunStatus.OK,
            message="Ingested cisa-kev.",
            item_count=3,
            started_at=started_at,
            ended_at=ended_at,
        )
    )

    assert stored.run_id is not None

    runs = storage.list_source_runs()
    assert len(runs) == 1
    assert runs[0].run_id == stored.run_id
    assert runs[0].source_id == "cisa-kev"
    assert runs[0].status == SourceRunStatus.OK
    assert runs[0].item_count == 3
    assert runs[0].error_message is None
