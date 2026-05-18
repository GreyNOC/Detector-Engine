from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel

from greynoc_detector_engine.models.cve import CVERecord
from greynoc_detector_engine.models.detection import GeneratedDetection
from greynoc_detector_engine.models.kev import KEVRecord
from greynoc_detector_engine.models.scoring import ScoreResult
from greynoc_detector_engine.models.source import SourceItem, SourceRun
from greynoc_detector_engine.models.threat import ThreatRecord
from greynoc_detector_engine.storage.base import StorageBackend

ModelT = TypeVar("ModelT", bound=BaseModel)


class SQLiteStorage(StorageBackend):
    def __init__(self, path: Path) -> None:
        self.path = path

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS cves (
                    cve_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS kev_entries (
                    cve_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS threats (
                    threat_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS detections (
                    detection_id TEXT PRIMARY KEY,
                    related_threat_id TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS raw_items (
                    item_id TEXT PRIMARY KEY,
                    source_id TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS source_runs (
                    run_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    message TEXT NOT NULL,
                    item_count INTEGER NOT NULL DEFAULT 0,
                    started_at TEXT NOT NULL,
                    ended_at TEXT NOT NULL,
                    error_message TEXT,
                    payload TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS score_events (
                    score_event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id TEXT NOT NULL,
                    score_type TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_detections_threat
                    ON detections (related_threat_id);
                CREATE INDEX IF NOT EXISTS idx_raw_items_source
                    ON raw_items (source_id);
                CREATE INDEX IF NOT EXISTS idx_source_runs_source_created
                    ON source_runs (source_id, created_at);
                CREATE INDEX IF NOT EXISTS idx_source_runs_status_created
                    ON source_runs (status, created_at);
                CREATE INDEX IF NOT EXISTS idx_score_events_target
                    ON score_events (target_id);
                """
            )
            self._migrate_source_runs(conn)

    def upsert_cve(self, record: CVERecord) -> None:
        self._upsert("cves", "cve_id", record.cve_id, record)

    def list_cves(self) -> list[CVERecord]:
        return self._list("cves", CVERecord)

    def get_cve(self, cve_id: str) -> CVERecord | None:
        return self._get("cves", "cve_id", cve_id, CVERecord)

    def upsert_kev(self, record: KEVRecord) -> None:
        self._upsert("kev_entries", "cve_id", record.cve_id, record)

    def list_kev(self) -> list[KEVRecord]:
        return self._list("kev_entries", KEVRecord)

    def get_kev(self, cve_id: str) -> KEVRecord | None:
        return self._get("kev_entries", "cve_id", cve_id, KEVRecord)

    def upsert_threat(self, record: ThreatRecord) -> None:
        self._upsert_with_extra(
            "threats",
            "threat_id",
            record.threat_id,
            record,
            extra_columns={"title": record.title},
        )

    def list_threats(self) -> list[ThreatRecord]:
        return self._list("threats", ThreatRecord)

    def get_threat(self, threat_id: str) -> ThreatRecord | None:
        return self._get("threats", "threat_id", threat_id, ThreatRecord)

    def upsert_detection(self, record: GeneratedDetection) -> None:
        self._upsert_with_extra(
            "detections",
            "detection_id",
            record.detection_id,
            record,
            extra_columns={"related_threat_id": record.related_threat_id},
        )

    def list_detections(self) -> list[GeneratedDetection]:
        return self._list("detections", GeneratedDetection)

    def get_detection(self, detection_id: str) -> GeneratedDetection | None:
        return self._get("detections", "detection_id", detection_id, GeneratedDetection)

    def upsert_raw_item(self, record: SourceItem) -> None:
        self._upsert_with_extra(
            "raw_items",
            "item_id",
            record.item_id,
            record,
            extra_columns={"source_id": record.source_id},
        )

    def list_raw_items(self) -> list[SourceItem]:
        return self._list("raw_items", SourceItem)

    def upsert_source_item(self, record: SourceItem) -> None:
        self.upsert_raw_item(record)

    def list_source_items(self) -> list[SourceItem]:
        return self.list_raw_items()

    def record_source_run(self, run: SourceRun) -> SourceRun:
        run_to_store = run.model_copy(update={"run_id": None})
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO source_runs (
                    source_id, status, message, item_count, started_at, ended_at,
                    error_message, payload, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_to_store.source_id,
                    run_to_store.status.value,
                    run_to_store.message,
                    run_to_store.item_count,
                    run_to_store.started_at.isoformat(),
                    run_to_store.ended_at.isoformat(),
                    run_to_store.error_message,
                    run_to_store.model_dump_json(),
                    run_to_store.created_at.isoformat(),
                ),
            )
            lastrowid = cursor.lastrowid
            if lastrowid is None:
                raise RuntimeError("SQLite did not return a source run id after insert.")
            run_id = int(lastrowid)
        return run_to_store.model_copy(update={"run_id": run_id})

    def list_source_runs(self, limit: int = 100) -> list[SourceRun]:
        bounded_limit = max(1, min(limit, 500))
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT run_id, payload FROM source_runs "
                "ORDER BY created_at DESC, run_id DESC LIMIT ?",
                (bounded_limit,),
            ).fetchall()
        runs: list[SourceRun] = []
        for row in rows:
            run = SourceRun.model_validate_json(row["payload"])
            runs.append(run.model_copy(update={"run_id": row["run_id"]}))
        return runs

    def record_score_event(self, target_id: str, score_type: str, score: ScoreResult) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO score_events (target_id, score_type, payload, created_at)
                VALUES (?, ?, ?, datetime('now'))
                """,
                (target_id, score_type, score.model_dump_json()),
            )

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def _migrate_source_runs(self, conn: sqlite3.Connection) -> None:
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(source_runs)").fetchall()}
        required = {
            "item_count": "INTEGER NOT NULL DEFAULT 0",
            "started_at": "TEXT",
            "ended_at": "TEXT",
            "error_message": "TEXT",
            "payload": "TEXT",
        }
        for column, definition in required.items():
            if column not in columns:
                conn.execute(f"ALTER TABLE source_runs ADD COLUMN {column} {definition}")

        rows = conn.execute(
            "SELECT run_id, source_id, status, message, created_at "
            "FROM source_runs WHERE payload IS NULL"
        ).fetchall()
        for row in rows:
            run = SourceRun(
                run_id=row["run_id"],
                source_id=row["source_id"],
                status=row["status"],
                message=row["message"],
                item_count=0,
                started_at=row["created_at"],
                ended_at=row["created_at"],
                created_at=row["created_at"],
            )
            conn.execute(
                """
                UPDATE source_runs
                SET item_count = ?, started_at = ?, ended_at = ?, error_message = ?, payload = ?
                WHERE run_id = ?
                """,
                (
                    run.item_count,
                    run.started_at.isoformat(),
                    run.ended_at.isoformat(),
                    run.error_message,
                    run.model_dump_json(),
                    run.run_id,
                ),
            )

    def _upsert(self, table: str, key_column: str, key_value: str, model: BaseModel) -> None:
        self._upsert_with_extra(table, key_column, key_value, model, extra_columns={})

    def _upsert_with_extra(
        self,
        table: str,
        key_column: str,
        key_value: str,
        model: BaseModel,
        *,
        extra_columns: dict[str, str],
    ) -> None:
        columns = [key_column, *extra_columns.keys(), "payload"]
        placeholders = ", ".join("?" for _ in columns)
        update_clause = ", ".join(f"{column}=excluded.{column}" for column in columns[1:])
        values = [key_value, *extra_columns.values(), model.model_dump_json()]
        sql = (
            f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({placeholders}) "
            f"ON CONFLICT({key_column}) DO UPDATE SET {update_clause}"
        )
        with self._connect() as conn:
            conn.execute(sql, values)

    def _list(self, table: str, model_type: type[ModelT]) -> list[ModelT]:
        with self._connect() as conn:
            rows = conn.execute(f"SELECT payload FROM {table}").fetchall()
        return [model_type.model_validate_json(row["payload"]) for row in rows]

    def _get(
        self,
        table: str,
        key_column: str,
        key_value: str,
        model_type: type[ModelT],
    ) -> ModelT | None:
        with self._connect() as conn:
            row = conn.execute(
                f"SELECT payload FROM {table} WHERE {key_column} = ?",
                (key_value,),
            ).fetchone()
        if row is None:
            return None
        return model_type.model_validate_json(row["payload"])
