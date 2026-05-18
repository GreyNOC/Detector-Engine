from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel

from greynoc_detector_engine.models.cve import CVERecord
from greynoc_detector_engine.models.detection import GeneratedDetection
from greynoc_detector_engine.models.kev import KEVRecord
from greynoc_detector_engine.models.scoring import ScoreResult
from greynoc_detector_engine.models.source import SourceItem
from greynoc_detector_engine.models.threat import ThreatRecord
from greynoc_detector_engine.storage.base import StorageBackend
from greynoc_detector_engine.utils.time import utc_now

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
                CREATE INDEX IF NOT EXISTS idx_score_events_target
                    ON score_events (target_id);
                """
            )

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

    def record_source_run(self, source_id: str, status: str, message: str) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO source_runs (source_id, status, message, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (source_id, status, message, utc_now().isoformat()),
            )

    def record_score_event(self, target_id: str, score_type: str, score: ScoreResult) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO score_events (target_id, score_type, payload, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (target_id, score_type, score.model_dump_json(), utc_now().isoformat()),
            )

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

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
