"""Versioned SQLite migrations for the detection engine.

The first time the engine opens a database it stamps ``user_version`` and
applies every migration whose target version is higher. Migrations are
small, idempotent, and never destructive — schema-only or backfilled
adds. We bump ``CURRENT_USER_VERSION`` whenever we add a migration.
"""

from __future__ import annotations

import sqlite3

CURRENT_USER_VERSION = 5

_MIGRATIONS: dict[int, list[str]] = {
    1: [
        # Performance / concurrency. Safe to run repeatedly.
        "PRAGMA journal_mode = WAL;",
        "PRAGMA synchronous = NORMAL;",
        "PRAGMA temp_store = MEMORY;",
        "PRAGMA mmap_size = 268435456;",  # 256 MiB
    ],
    2: [
        # Hot-path indexes we discovered during profiling.
        "CREATE INDEX IF NOT EXISTS idx_threats_title ON threats (title);",
        "CREATE INDEX IF NOT EXISTS idx_score_events_type ON score_events (score_type);",
        (
            "CREATE INDEX IF NOT EXISTS idx_attack_forecasts_generated "
            "ON attack_forecasts (generated_at);"
        ),
    ],
    3: [
        # Feedback table for analyst verdicts.
        """
        CREATE TABLE IF NOT EXISTS threat_feedback (
            feedback_id TEXT PRIMARY KEY,
            threat_id TEXT NOT NULL,
            verdict TEXT NOT NULL,
            analyst TEXT NOT NULL,
            payload TEXT NOT NULL,
            submitted_at TEXT NOT NULL
        );
        """,
        "CREATE INDEX IF NOT EXISTS idx_threat_feedback_threat ON threat_feedback (threat_id);",
    ],
    4: [
        # Adaptive scan baselines + source health + forecast outcomes.
        """
        CREATE TABLE IF NOT EXISTS scan_baselines (
            source_address TEXT PRIMARY KEY,
            payload TEXT NOT NULL,
            last_updated TEXT NOT NULL
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS source_health (
            source_id TEXT PRIMARY KEY,
            payload TEXT NOT NULL,
            checked_at TEXT NOT NULL
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS forecast_outcomes (
            outcome_id INTEGER PRIMARY KEY AUTOINCREMENT,
            threat_id TEXT NOT NULL,
            forecast_probability REAL NOT NULL,
            forecast_horizon TEXT NOT NULL,
            verified_attack INTEGER NOT NULL,
            verified_at TEXT NOT NULL,
            notes TEXT NOT NULL DEFAULT ''
        );
        """,
        "CREATE INDEX IF NOT EXISTS idx_forecast_outcomes_threat ON forecast_outcomes (threat_id);",
    ],
    5: [
        """
        CREATE TABLE IF NOT EXISTS forecast_runs (
            run_id INTEGER PRIMARY KEY AUTOINCREMENT,
            payload TEXT NOT NULL,
            started_at TEXT NOT NULL,
            ended_at TEXT NOT NULL,
            model_version TEXT NOT NULL
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS prediction_fingerprints (
            threat_id TEXT PRIMARY KEY,
            fingerprint TEXT NOT NULL,
            model_version TEXT NOT NULL,
            payload TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        """,
        (
            "DELETE FROM target_likelihoods "
            "WHERE likelihood_id NOT IN ("
            "SELECT MAX(likelihood_id) FROM target_likelihoods GROUP BY asset_id, threat_id"
            ");"
        ),
        (
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_target_likelihoods_asset_threat "
            "ON target_likelihoods (asset_id, threat_id);"
        ),
        "CREATE INDEX IF NOT EXISTS idx_forecast_runs_started ON forecast_runs (started_at);",
        (
            "CREATE INDEX IF NOT EXISTS idx_prediction_fingerprints_model "
            "ON prediction_fingerprints (model_version);"
        ),
    ],
}


def apply_pending(conn: sqlite3.Connection) -> int:
    """Bring the open connection up to ``CURRENT_USER_VERSION``.

    Returns the number of migrations applied.
    """
    current = conn.execute("PRAGMA user_version;").fetchone()[0]
    applied = 0
    for version in sorted(_MIGRATIONS):
        if version <= current:
            continue
        for stmt in _MIGRATIONS[version]:
            conn.executescript(stmt)
        conn.execute(f"PRAGMA user_version = {version};")
        applied += 1
    return applied
