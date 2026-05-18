from __future__ import annotations

import sqlite3
from pathlib import Path

from greynoc_detector_engine.storage.migrations import (
    CURRENT_USER_VERSION,
    apply_pending,
)
from greynoc_detector_engine.storage.sqlite import SQLiteStorage
from greynoc_detector_engine.workers.health import (
    run_safety_self_check,
    run_source_health,
)


def test_migrations_apply_idempotently(tmp_path: Path) -> None:
    db_path = tmp_path / "t.sqlite"
    storage = SQLiteStorage(db_path)
    storage.initialize()
    # Apply again — must be a no-op without raising.
    storage.initialize()
    with sqlite3.connect(db_path) as conn:
        version = conn.execute("PRAGMA user_version;").fetchone()[0]
    assert version == CURRENT_USER_VERSION


def test_migration_creates_feedback_table(tmp_path: Path) -> None:
    db_path = tmp_path / "t.sqlite"
    SQLiteStorage(db_path).initialize()
    with sqlite3.connect(db_path) as conn:
        tables = {
            row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
    assert "threat_feedback" in tables
    assert "forecast_outcomes" in tables
    assert "forecast_runs" in tables
    assert "prediction_fingerprints" in tables
    assert "scan_baselines" in tables


def test_apply_pending_returns_zero_when_current(tmp_path: Path) -> None:
    db_path = tmp_path / "t.sqlite"
    SQLiteStorage(db_path).initialize()
    with sqlite3.connect(db_path) as conn:
        applied = apply_pending(conn)
    assert applied == 0


def test_safety_self_check_is_all_ok() -> None:
    report = run_safety_self_check()
    assert report.exit_code == 0
    severities = {f.severity for f in report.findings}
    assert "fail" not in severities


def test_source_health_warns_when_no_runs(tmp_path: Path) -> None:
    db_path = tmp_path / "t.sqlite"
    storage = SQLiteStorage(db_path)
    storage.initialize()
    report = run_source_health(storage)
    # No runs yet → exactly one "warn" finding.
    assert report.exit_code >= 1
    assert any(f.severity == "warn" for f in report.findings)
