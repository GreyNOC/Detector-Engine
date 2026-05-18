from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel

from greynoc_detector_engine.enrich.reputation import IndicatorReputation
from greynoc_detector_engine.models.asset import AssetRecord, TargetLikelihood
from greynoc_detector_engine.models.cve import CVERecord
from greynoc_detector_engine.models.detection import GeneratedDetection
from greynoc_detector_engine.models.feedback import ThreatFeedback
from greynoc_detector_engine.models.kev import KEVRecord
from greynoc_detector_engine.models.network import (
    HoneypotEvent,
    ICSObservation,
    IntrusionSignal,
    NetworkDevice,
)
from greynoc_detector_engine.models.prediction import (
    AttackForecast,
    CampaignCluster,
    EPSSScore,
)
from greynoc_detector_engine.models.scoring import ScoreResult
from greynoc_detector_engine.models.source import SourceItem
from greynoc_detector_engine.models.threat import ThreatRecord
from greynoc_detector_engine.spacestation.adaptive import HostBaseline
from greynoc_detector_engine.storage.base import StorageBackend
from greynoc_detector_engine.storage.migrations import apply_pending
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
                CREATE TABLE IF NOT EXISTS epss_scores (
                    cve_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS campaigns (
                    campaign_id TEXT PRIMARY KEY,
                    label TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS attack_forecasts (
                    forecast_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    threat_id TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    generated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS indicator_reputation (
                    indicator_key TEXT PRIMARY KEY,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS assets (
                    asset_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS target_likelihoods (
                    likelihood_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    asset_id TEXT NOT NULL,
                    threat_id TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS network_devices (
                    device_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    last_seen TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS ics_observations (
                    observation_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    observed_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS intrusion_signals (
                    signal_id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    last_seen TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS honeypot_events (
                    event_id TEXT PRIMARY KEY,
                    listener_port INTEGER NOT NULL,
                    payload TEXT NOT NULL,
                    observed_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_detections_threat
                    ON detections (related_threat_id);
                CREATE INDEX IF NOT EXISTS idx_raw_items_source
                    ON raw_items (source_id);
                CREATE INDEX IF NOT EXISTS idx_score_events_target
                    ON score_events (target_id);
                CREATE INDEX IF NOT EXISTS idx_attack_forecasts_threat
                    ON attack_forecasts (threat_id);
                CREATE INDEX IF NOT EXISTS idx_target_likelihoods_threat
                    ON target_likelihoods (threat_id);
                CREATE INDEX IF NOT EXISTS idx_ics_observations_device
                    ON ics_observations (device_id);
                CREATE INDEX IF NOT EXISTS idx_intrusion_signals_kind
                    ON intrusion_signals (kind);
                CREATE INDEX IF NOT EXISTS idx_honeypot_events_port
                    ON honeypot_events (listener_port);
                """
            )
            apply_pending(conn)

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

    def upsert_epss(self, score: EPSSScore) -> None:
        self._upsert("epss_scores", "cve_id", score.cve_id, score)

    def list_epss(self) -> list[EPSSScore]:
        return self._list("epss_scores", EPSSScore)

    def get_epss(self, cve_id: str) -> EPSSScore | None:
        return self._get("epss_scores", "cve_id", cve_id, EPSSScore)

    def upsert_campaign(self, campaign: CampaignCluster) -> None:
        self._upsert_with_extra(
            "campaigns",
            "campaign_id",
            campaign.campaign_id,
            campaign,
            extra_columns={"label": campaign.label},
        )

    def list_campaigns(self) -> list[CampaignCluster]:
        return self._list("campaigns", CampaignCluster)

    def get_campaign(self, campaign_id: str) -> CampaignCluster | None:
        return self._get("campaigns", "campaign_id", campaign_id, CampaignCluster)

    def record_attack_forecast(self, threat_id: str, forecast: AttackForecast) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO attack_forecasts (threat_id, payload, generated_at)
                VALUES (?, ?, ?)
                """,
                (threat_id, forecast.model_dump_json(), forecast.generated_at.isoformat()),
            )

    def list_forecasts_for_threat(self, threat_id: str) -> list[AttackForecast]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT payload FROM attack_forecasts WHERE threat_id = ? ORDER BY generated_at",
                (threat_id,),
            ).fetchall()
        return [AttackForecast.model_validate_json(row["payload"]) for row in rows]

    def upsert_indicator_reputation(self, reputation: IndicatorReputation) -> None:
        key = f"{reputation.type.value}:{reputation.value.lower()}"
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO indicator_reputation (indicator_key, payload)
                VALUES (?, ?)
                ON CONFLICT(indicator_key) DO UPDATE SET payload=excluded.payload
                """,
                (key, reputation.model_dump_json()),
            )

    def list_indicator_reputation(self) -> list[IndicatorReputation]:
        with self._connect() as conn:
            rows = conn.execute("SELECT payload FROM indicator_reputation").fetchall()
        return [IndicatorReputation.model_validate_json(row["payload"]) for row in rows]

    def upsert_asset(self, asset: AssetRecord) -> None:
        self._upsert("assets", "asset_id", asset.asset_id, asset)

    def list_assets(self) -> list[AssetRecord]:
        return self._list("assets", AssetRecord)

    def record_target_likelihood(self, likelihood: TargetLikelihood) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO target_likelihoods (asset_id, threat_id, payload)
                VALUES (?, ?, ?)
                """,
                (likelihood.asset_id, likelihood.threat_id, likelihood.model_dump_json()),
            )

    def list_target_likelihoods_for_threat(self, threat_id: str) -> list[TargetLikelihood]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT payload FROM target_likelihoods WHERE threat_id = ?",
                (threat_id,),
            ).fetchall()
        return [TargetLikelihood.model_validate_json(row["payload"]) for row in rows]

    # -- network / ICS / spacestation ---------------------------------------

    def upsert_network_device(self, device: NetworkDevice) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO network_devices (device_id, payload, last_seen)
                VALUES (?, ?, ?)
                ON CONFLICT(device_id) DO UPDATE
                  SET payload=excluded.payload, last_seen=excluded.last_seen
                """,
                (device.device_id, device.model_dump_json(), device.last_seen.isoformat()),
            )

    def list_network_devices(self) -> list[NetworkDevice]:
        with self._connect() as conn:
            rows = conn.execute("SELECT payload FROM network_devices").fetchall()
        return [NetworkDevice.model_validate_json(row["payload"]) for row in rows]

    def record_ics_observation(self, observation: ICSObservation) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO ics_observations (device_id, payload, observed_at)
                VALUES (?, ?, ?)
                """,
                (
                    observation.device_id,
                    observation.model_dump_json(),
                    observation.observed_at.isoformat(),
                ),
            )

    def list_ics_observations(self) -> list[ICSObservation]:
        with self._connect() as conn:
            rows = conn.execute("SELECT payload FROM ics_observations").fetchall()
        return [ICSObservation.model_validate_json(row["payload"]) for row in rows]

    def upsert_intrusion_signal(self, signal: IntrusionSignal) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO intrusion_signals (signal_id, kind, severity, payload, last_seen)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(signal_id) DO UPDATE
                  SET payload=excluded.payload, last_seen=excluded.last_seen
                """,
                (
                    signal.signal_id,
                    signal.kind.value,
                    signal.severity.value,
                    signal.model_dump_json(),
                    signal.last_seen.isoformat(),
                ),
            )

    def list_intrusion_signals(self) -> list[IntrusionSignal]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT payload FROM intrusion_signals ORDER BY last_seen DESC"
            ).fetchall()
        return [IntrusionSignal.model_validate_json(row["payload"]) for row in rows]

    def record_honeypot_event(self, event: HoneypotEvent) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO honeypot_events (event_id, listener_port, payload, observed_at)
                VALUES (?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.listener_port,
                    event.model_dump_json(),
                    event.observed_at.isoformat(),
                ),
            )

    def list_honeypot_events(self) -> list[HoneypotEvent]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT payload FROM honeypot_events ORDER BY observed_at DESC"
            ).fetchall()
        return [HoneypotEvent.model_validate_json(row["payload"]) for row in rows]

    # -- analyst feedback / adaptive baselines / forecast outcomes ---------

    def upsert_threat_feedback(self, feedback: ThreatFeedback) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO threat_feedback
                    (feedback_id, threat_id, verdict, analyst, payload, submitted_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(feedback_id) DO UPDATE
                  SET payload=excluded.payload, submitted_at=excluded.submitted_at
                """,
                (
                    feedback.feedback_id,
                    feedback.threat_id,
                    feedback.verdict.value,
                    feedback.analyst,
                    feedback.model_dump_json(),
                    feedback.submitted_at.isoformat(),
                ),
            )

    def list_threat_feedback(self) -> list[ThreatFeedback]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT payload FROM threat_feedback ORDER BY submitted_at DESC"
            ).fetchall()
        return [ThreatFeedback.model_validate_json(row["payload"]) for row in rows]

    def upsert_scan_baseline(self, baseline: HostBaseline) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO scan_baselines (source_address, payload, last_updated)
                VALUES (?, ?, ?)
                ON CONFLICT(source_address) DO UPDATE
                  SET payload=excluded.payload, last_updated=excluded.last_updated
                """,
                (
                    baseline.source_address,
                    baseline.model_dump_json(),
                    baseline.last_updated.isoformat(),
                ),
            )

    def list_scan_baselines(self) -> list[HostBaseline]:
        with self._connect() as conn:
            rows = conn.execute("SELECT payload FROM scan_baselines").fetchall()
        return [HostBaseline.model_validate_json(row["payload"]) for row in rows]

    def record_forecast_outcome(
        self,
        *,
        threat_id: str,
        forecast_probability: float,
        forecast_horizon: str,
        verified_attack: bool,
        notes: str = "",
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO forecast_outcomes
                    (threat_id, forecast_probability, forecast_horizon,
                     verified_attack, verified_at, notes)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    threat_id,
                    float(forecast_probability),
                    forecast_horizon,
                    1 if verified_attack else 0,
                    utc_now().isoformat(),
                    notes,
                ),
            )

    def list_forecast_outcomes(self) -> list[dict[str, object]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT threat_id, forecast_probability, forecast_horizon, "
                "verified_attack, verified_at, notes "
                "FROM forecast_outcomes ORDER BY verified_at DESC"
            ).fetchall()
        return [dict(row) for row in rows]

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
