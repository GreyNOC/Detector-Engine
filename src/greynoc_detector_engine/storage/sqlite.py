from __future__ import annotations

import sqlite3
from collections.abc import Iterator
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
    ForecastRun,
    PredictionFingerprint,
)
from greynoc_detector_engine.models.scoring import ScoreEvent, ScoreResult
from greynoc_detector_engine.models.source import SourceItem, SourceRun
from greynoc_detector_engine.models.threat import ThreatRecord
from greynoc_detector_engine.spacestation.adaptive import HostBaseline
from greynoc_detector_engine.storage.base import StorageBackend
from greynoc_detector_engine.storage.migrations import apply_pending
from greynoc_detector_engine.utils.time import parse_datetime, utc_now

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
                CREATE TABLE IF NOT EXISTS forecast_runs (
                    run_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    payload TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    ended_at TEXT NOT NULL,
                    model_version TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS prediction_fingerprints (
                    threat_id TEXT PRIMARY KEY,
                    fingerprint TEXT NOT NULL,
                    model_version TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    updated_at TEXT NOT NULL
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
                CREATE INDEX IF NOT EXISTS idx_source_runs_source_created
                    ON source_runs (source_id, created_at);
                CREATE INDEX IF NOT EXISTS idx_source_runs_status_created
                    ON source_runs (status, created_at);
                CREATE INDEX IF NOT EXISTS idx_score_events_target
                    ON score_events (target_id);
                CREATE INDEX IF NOT EXISTS idx_score_events_type_created
                    ON score_events (score_type, created_at);
                CREATE INDEX IF NOT EXISTS idx_attack_forecasts_threat
                    ON attack_forecasts (threat_id);
                CREATE INDEX IF NOT EXISTS idx_target_likelihoods_threat
                    ON target_likelihoods (threat_id);
                CREATE INDEX IF NOT EXISTS idx_forecast_runs_started
                    ON forecast_runs (started_at);
                CREATE INDEX IF NOT EXISTS idx_prediction_fingerprints_model
                    ON prediction_fingerprints (model_version);
                CREATE INDEX IF NOT EXISTS idx_ics_observations_device
                    ON ics_observations (device_id);
                CREATE INDEX IF NOT EXISTS idx_intrusion_signals_kind
                    ON intrusion_signals (kind);
                CREATE INDEX IF NOT EXISTS idx_honeypot_events_port
                    ON honeypot_events (listener_port);
                """
            )
            self._migrate_source_runs(conn)
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

    def iter_threats(self, batch_size: int = 500) -> Iterator[list[ThreatRecord]]:
        bounded_batch = max(1, min(batch_size, 5000))
        offset = 0
        while True:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT payload FROM threats ORDER BY threat_id LIMIT ? OFFSET ?",
                    (bounded_batch, offset),
                ).fetchall()
            if not rows:
                break
            yield [ThreatRecord.model_validate_json(row["payload"]) for row in rows]
            offset += bounded_batch

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

    def list_raw_items_for_cves(self, cve_ids: list[str]) -> list[SourceItem]:
        normalized = sorted({cve_id.upper() for cve_id in cve_ids})
        if not normalized:
            return []
        conditions = " OR ".join("payload LIKE ?" for _ in normalized)
        values = [f"%{cve_id}%" for cve_id in normalized]
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT payload FROM raw_items WHERE {conditions}",
                values,
            ).fetchall()
        return [SourceItem.model_validate_json(row["payload"]) for row in rows]

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

    def get_latest_forecast_for_threat(self, threat_id: str) -> AttackForecast | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT payload FROM attack_forecasts WHERE threat_id = ? "
                "ORDER BY generated_at DESC, forecast_id DESC LIMIT 1",
                (threat_id,),
            ).fetchone()
        if row is None:
            return None
        return AttackForecast.model_validate_json(row["payload"])

    def record_forecast_run(self, run: ForecastRun) -> ForecastRun:
        run_to_store = run.model_copy(update={"run_id": None})
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO forecast_runs (payload, started_at, ended_at, model_version)
                VALUES (?, ?, ?, ?)
                """,
                (
                    run_to_store.model_dump_json(),
                    run_to_store.started_at.isoformat(),
                    run_to_store.ended_at.isoformat(),
                    run_to_store.model_version,
                ),
            )
            lastrowid = cursor.lastrowid
            if lastrowid is None:
                raise RuntimeError("SQLite did not return a forecast run id after insert.")
            run_id = int(lastrowid)
        return run_to_store.model_copy(update={"run_id": run_id})

    def list_forecast_runs(self, limit: int = 100) -> list[ForecastRun]:
        bounded_limit = max(1, min(limit, 500))
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT run_id, payload FROM forecast_runs "
                "ORDER BY started_at DESC, run_id DESC LIMIT ?",
                (bounded_limit,),
            ).fetchall()
        out: list[ForecastRun] = []
        for row in rows:
            run = ForecastRun.model_validate_json(row["payload"])
            out.append(run.model_copy(update={"run_id": row["run_id"]}))
        return out

    def get_prediction_fingerprint(self, threat_id: str) -> PredictionFingerprint | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT payload FROM prediction_fingerprints WHERE threat_id = ?",
                (threat_id,),
            ).fetchone()
        if row is None:
            return None
        return PredictionFingerprint.model_validate_json(row["payload"])

    def upsert_prediction_fingerprint(self, fingerprint: PredictionFingerprint) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO prediction_fingerprints (
                    threat_id, fingerprint, model_version, payload, updated_at
                )
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(threat_id) DO UPDATE
                  SET fingerprint=excluded.fingerprint,
                      model_version=excluded.model_version,
                      payload=excluded.payload,
                      updated_at=excluded.updated_at
                """,
                (
                    fingerprint.threat_id,
                    fingerprint.fingerprint,
                    fingerprint.model_version,
                    fingerprint.model_dump_json(),
                    fingerprint.updated_at.isoformat(),
                ),
            )

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
                ON CONFLICT(asset_id, threat_id) DO UPDATE SET payload=excluded.payload
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

    def record_prediction_batch(
        self,
        *,
        threats: list[ThreatRecord],
        forecasts: list[tuple[str, AttackForecast]],
        score_events: list[tuple[str, str, ScoreResult]],
        target_likelihoods: list[TargetLikelihood],
        fingerprints: list[PredictionFingerprint],
    ) -> None:
        with self._connect() as conn:
            for threat in threats:
                conn.execute(
                    """
                    INSERT INTO threats (threat_id, title, payload)
                    VALUES (?, ?, ?)
                    ON CONFLICT(threat_id) DO UPDATE
                      SET title=excluded.title, payload=excluded.payload
                    """,
                    (threat.threat_id, threat.title, threat.model_dump_json()),
                )
            for threat_id, forecast in forecasts:
                conn.execute(
                    """
                    INSERT INTO attack_forecasts (threat_id, payload, generated_at)
                    VALUES (?, ?, ?)
                    """,
                    (threat_id, forecast.model_dump_json(), forecast.generated_at.isoformat()),
                )
            for target_id, score_type, score in score_events:
                conn.execute(
                    """
                    INSERT INTO score_events (target_id, score_type, payload, created_at)
                    VALUES (?, ?, ?, datetime('now'))
                    """,
                    (target_id, score_type, score.model_dump_json()),
                )
            for likelihood in target_likelihoods:
                conn.execute(
                    """
                    INSERT INTO target_likelihoods (asset_id, threat_id, payload)
                    VALUES (?, ?, ?)
                    ON CONFLICT(asset_id, threat_id) DO UPDATE SET payload=excluded.payload
                    """,
                    (
                        likelihood.asset_id,
                        likelihood.threat_id,
                        likelihood.model_dump_json(),
                    ),
                )
            for fingerprint in fingerprints:
                conn.execute(
                    """
                    INSERT INTO prediction_fingerprints (
                        threat_id, fingerprint, model_version, payload, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(threat_id) DO UPDATE
                      SET fingerprint=excluded.fingerprint,
                          model_version=excluded.model_version,
                          payload=excluded.payload,
                          updated_at=excluded.updated_at
                    """,
                    (
                        fingerprint.threat_id,
                        fingerprint.fingerprint,
                        fingerprint.model_version,
                        fingerprint.model_dump_json(),
                        fingerprint.updated_at.isoformat(),
                    ),
                )

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
                VALUES (?, ?, ?, datetime('now'))
                """,
                (target_id, score_type, score.model_dump_json()),
            )

    def list_score_events(
        self,
        *,
        target_id: str | None = None,
        score_type: str | None = None,
        limit: int = 100,
    ) -> list[ScoreEvent]:
        bounded_limit = max(1, min(limit, 500))
        conditions: list[str] = []
        values: list[object] = []
        if target_id is not None:
            conditions.append("target_id = ?")
            values.append(target_id)
        if score_type is not None:
            conditions.append("score_type = ?")
            values.append(score_type)
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = (
            "SELECT score_event_id, target_id, score_type, payload, created_at "
            f"FROM score_events {where} "
            "ORDER BY created_at DESC, score_event_id DESC LIMIT ?"
        )
        values.append(bounded_limit)
        with self._connect() as conn:
            rows = conn.execute(sql, values).fetchall()
        events: list[ScoreEvent] = []
        for row in rows:
            created_at = parse_datetime(row["created_at"])
            if created_at is None:
                continue
            events.append(
                ScoreEvent(
                    score_event_id=row["score_event_id"],
                    target_id=row["target_id"],
                    score_type=row["score_type"],
                    score=ScoreResult.model_validate_json(row["payload"]),
                    created_at=created_at,
                )
            )
        return events

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
