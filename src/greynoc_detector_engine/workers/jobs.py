from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from greynoc_detector_engine.analysis.correlation import CorrelationEngine
from greynoc_detector_engine.catalog.threat_library import ThreatLibrary
from greynoc_detector_engine.config.settings import Settings, load_source_registry
from greynoc_detector_engine.config.source_registry import SourceRegistry
from greynoc_detector_engine.detection.generators import DetectionGeneratorSuite
from greynoc_detector_engine.enrichment.epss import EPSSClient, enrich_cves_with_epss
from greynoc_detector_engine.ingest.cve import CVEIngestor
from greynoc_detector_engine.ingest.github import GitHubIngestor
from greynoc_detector_engine.ingest.kev import KEVIngestor
from greynoc_detector_engine.ingest.news import NewsIngestor
from greynoc_detector_engine.ingest.rss import RSSIngestor
from greynoc_detector_engine.models.detection import (
    DetectionStatus,
    ValidationEvidence,
    ValidationResult,
)
from greynoc_detector_engine.models.source import (
    SourceConfig,
    SourceRun,
    SourceRunStatus,
    SourceType,
)
from greynoc_detector_engine.models.threat import ThreatSeverity
from greynoc_detector_engine.scoring.ai_attack_score import AIAttackScorer
from greynoc_detector_engine.scoring.exploitability import ExploitabilityScorer
from greynoc_detector_engine.scoring.risk import RiskScorer
from greynoc_detector_engine.storage.base import StorageBackend
from greynoc_detector_engine.storage.sqlite import SQLiteStorage
from greynoc_detector_engine.utils.time import utc_now

IngestSourceName = Literal["cve", "kev", "news", "rss", "github"]


class DetectionLifecycleError(ValueError):
    pass


class JobResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    job: str
    status: str = "ok"
    counts: dict[str, int] = Field(default_factory=dict)
    messages: list[str] = Field(default_factory=list)


def build_storage(settings: Settings) -> SQLiteStorage:
    storage = SQLiteStorage(settings.database_path)
    storage.initialize()
    return storage


def initialize_project(settings: Settings) -> JobResult:
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    for child in ("raw", "normalized", "detections", "threat_library"):
        (settings.data_dir / child).mkdir(parents=True, exist_ok=True)
    build_storage(settings)
    return JobResult(job="init", counts={"directories": 4, "databases": 1})


def run_ingest_job(
    *,
    source: IngestSourceName,
    settings: Settings,
    storage: StorageBackend,
    fixture_path: Path | None = None,
    registry: SourceRegistry | None = None,
) -> JobResult:
    registry = registry or load_source_registry(settings.sources_path)
    configs = _configs_for_source(source, registry)
    if fixture_path and configs:
        configs = configs[:1]
    result = JobResult(job=f"ingest:{source}", counts={"records": 0})

    for config in configs:
        started_at = utc_now()
        item_count = 0
        try:
            item_count = _ingest_config(
                source=source,
                config=config,
                settings=settings,
                storage=storage,
                fixture_path=fixture_path,
            )
        except Exception as exc:
            ended_at = utc_now()
            storage.record_source_run(
                SourceRun(
                    source_id=config.source_id,
                    status=SourceRunStatus.FAILED,
                    message=f"Failed to ingest {config.source_id}.",
                    item_count=item_count,
                    started_at=started_at,
                    ended_at=ended_at,
                    error_message=str(exc),
                )
            )
            result.status = "failed"
            result.messages.append(f"Failed to ingest {config.source_id}: {exc}")
            raise

        ended_at = utc_now()
        storage.record_source_run(
            SourceRun(
                source_id=config.source_id,
                status=SourceRunStatus.OK,
                message=f"Ingested {config.source_id}.",
                item_count=item_count,
                started_at=started_at,
                ended_at=ended_at,
            )
        )
        result.counts["records"] += item_count
        result.messages.append(f"Ingested {config.source_id}.")

    if not configs:
        result.status = "skipped"
        result.messages.append(f"No enabled sources configured for {source}.")
    return result


def _ingest_config(
    *,
    source: IngestSourceName,
    config: SourceConfig,
    settings: Settings,
    storage: StorageBackend,
    fixture_path: Path | None,
) -> int:
    if source == "cve":
        cve_records = CVEIngestor(config, settings, fixture_path=fixture_path).ingest()
        for cve_record in cve_records:
            storage.upsert_cve(cve_record)
        return len(cve_records)
    if source == "kev":
        kev_records = KEVIngestor(config, settings, fixture_path=fixture_path).ingest()
        for kev_record in kev_records:
            storage.upsert_kev(kev_record)
        return len(kev_records)
    if source == "news":
        source_items = NewsIngestor(config, settings, fixture_path=fixture_path).ingest()
        for source_item in source_items:
            storage.upsert_raw_item(source_item)
        return len(source_items)
    if source == "rss":
        source_items = RSSIngestor(config, settings, fixture_path=fixture_path).ingest()
        for source_item in source_items:
            storage.upsert_raw_item(source_item)
        return len(source_items)
    if source == "github":
        source_items = GitHubIngestor(config, settings, fixture_path=fixture_path).ingest()
        for source_item in source_items:
            storage.upsert_raw_item(source_item)
        return len(source_items)
    return 0


def run_correlation_job(storage: StorageBackend) -> JobResult:
    report = CorrelationEngine().correlate(
        cves=storage.list_cves(),
        kev_entries=storage.list_kev(),
        source_items=storage.list_raw_items(),
    )
    library = ThreatLibrary(storage)
    for threat in report.threats:
        library.upsert(threat)
    return JobResult(
        job="correlate",
        counts={"threats": len(report.threats), "relationships": len(report.relationships)},
        messages=[relationship.reason for relationship in report.relationships[:10]],
    )


def run_epss_enrichment_job(
    *,
    settings: Settings,
    storage: StorageBackend,
    fixture_path: Path | None = None,
) -> JobResult:
    existing_cves = storage.list_cves()
    epss_records = EPSSClient(settings).load_records(fixture_path=fixture_path)
    enriched_cves = enrich_cves_with_epss(existing_cves, epss_records)
    changed = 0
    for before, after in zip(existing_cves, enriched_cves, strict=True):
        if before.epss_score != after.epss_score or before.tags != after.tags:
            storage.upsert_cve(after)
            changed += 1
    return JobResult(
        job="enrich:epss",
        counts={"cves": len(existing_cves), "epss_records": len(epss_records), "updated": changed},
    )


def run_score_job(storage: StorageBackend) -> JobResult:
    exploitability = ExploitabilityScorer()
    ai_attack = AIAttackScorer()
    risk = RiskScorer()
    count = 0
    for threat in storage.list_threats():
        cve = storage.get_cve(threat.related_cves[0]) if threat.related_cves else None
        kev = storage.get_kev(threat.related_cves[0]) if threat.related_cves else None
        updated = threat.model_copy(deep=True)
        updated.exploitability_score = exploitability.score(cve=cve, kev=kev, threat=updated)
        updated.ai_abuse_score = ai_attack.score(updated)
        risk_score = risk.score(threat=updated, cve=cve, kev=kev)
        if updated.exploitability_score:
            storage.record_score_event(
                updated.threat_id,
                "exploitability",
                updated.exploitability_score,
            )
        if updated.ai_abuse_score:
            storage.record_score_event(updated.threat_id, "ai_abuse", updated.ai_abuse_score)
        storage.record_score_event(updated.threat_id, "risk", risk_score)
        updated.severity = ThreatSeverity(risk_score.label.value)
        updated.changelog.append("Scores refreshed by score job.")
        storage.upsert_threat(updated)
        count += 1
    return JobResult(job="score", counts={"threats": count})


def generate_detections_for_threat(storage: StorageBackend, threat_id: str) -> JobResult:
    threat = storage.get_threat(threat_id)
    if threat is None:
        return JobResult(job="generate-detections", status="not_found", messages=[threat_id])

    existing_keys = {
        (detection.related_threat_id, detection.kind.value)
        for detection in storage.list_detections()
    }
    generated = []
    for detection in DetectionGeneratorSuite().generate_all(threat):
        key = (detection.related_threat_id, detection.kind.value)
        if key in existing_keys:
            continue
        storage.upsert_detection(detection)
        generated.append(detection)
    updated = threat.model_copy(deep=True)
    updated.generated_detections.extend(generated)
    if generated:
        updated.changelog.append(f"Generated {len(generated)} draft detections.")
    storage.upsert_threat(updated)
    return JobResult(job="generate-detections", counts={"detections": len(generated)})


def update_detection_status(
    storage: StorageBackend,
    detection_id: str,
    status: DetectionStatus,
    *,
    note: str | None = None,
    evidence: ValidationEvidence | None = None,
) -> JobResult:
    detection = storage.get_detection(detection_id)
    if detection is None:
        return JobResult(job="update-detection-status", status="not_found", messages=[detection_id])

    evidence_items = [*detection.validation_evidence]
    if evidence:
        evidence_items.append(evidence)
    _validate_detection_transition(status, note=note, evidence_items=evidence_items)

    updated = detection.model_copy(update={"status": status}, deep=True)
    if note:
        updated.validation_steps = [*updated.validation_steps, note]
    if evidence:
        updated.validation_evidence = [*updated.validation_evidence, evidence]
    storage.upsert_detection(updated)
    return JobResult(
        job="update-detection-status",
        counts={"detections": 1},
        messages=[f"Detection {detection_id} moved to {status.value}."]
        + ([note] if note else [])
        + ([evidence.summary] if evidence else []),
    )


def _validate_detection_transition(
    status: DetectionStatus,
    *,
    note: str | None,
    evidence_items: list[ValidationEvidence],
) -> None:
    if status == DetectionStatus.VALIDATED:
        passed_evidence = [item for item in evidence_items if item.result == ValidationResult.PASSED]
        if not passed_evidence:
            raise DetectionLifecycleError(
                "Validated detections require at least one passed validation evidence item."
            )
        if not any(item.telemetry_source for item in passed_evidence):
            raise DetectionLifecycleError(
                "Validated detections require validation evidence with a telemetry source."
            )
        if not any(item.reviewer for item in passed_evidence):
            raise DetectionLifecycleError(
                "Validated detections require validation evidence with a reviewer."
            )
        if not any(item.sample_size is not None and item.sample_size > 0 for item in passed_evidence):
            raise DetectionLifecycleError(
                "Validated detections require validation evidence with a positive sample size."
            )
        return

    if status == DetectionStatus.DEPRECATED and not note and not evidence_items:
        raise DetectionLifecycleError("Deprecated detections require a note or validation evidence.")


def generate_detections_for_all(storage: StorageBackend) -> JobResult:
    total = 0
    for threat in storage.list_threats():
        result = generate_detections_for_threat(storage, threat.threat_id)
        total += result.counts.get("detections", 0)
    return JobResult(job="generate-detections", counts={"detections": total})


def _configs_for_source(source: IngestSourceName, registry: SourceRegistry) -> list[SourceConfig]:
    if source == "cve":
        return registry.by_type(SourceType.CVE_JSON)
    if source == "kev":
        return registry.by_type(SourceType.KEV_JSON)
    if source == "github":
        return registry.by_type(SourceType.GITHUB_REPOSITORY) + registry.by_type(
            SourceType.GITHUB_SEARCH
        )
    if source == "rss":
        return registry.by_type(SourceType.RSS)
    if source == "news":
        return [
            config
            for config in registry.by_type(SourceType.RSS) + registry.by_type(SourceType.NEWS)
            if "news" in config.tags or config.category == "news"
        ]
    return []
