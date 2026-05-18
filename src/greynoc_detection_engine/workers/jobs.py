from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from greynoc_detection_engine.analysis.correlation_engine import CorrelationEngine
from greynoc_detection_engine.catalog.storage import SQLiteStorage, StorageBackend
from greynoc_detection_engine.catalog.threat_library import ThreatLibrary
from greynoc_detection_engine.config.settings import Settings, SourceRegistry, load_source_registry
from greynoc_detection_engine.detection.generators import DetectionGeneratorSuite
from greynoc_detection_engine.ingest.blog_ingestor import BlogIngestor
from greynoc_detection_engine.ingest.cve_ingestor import CVEIngestor
from greynoc_detection_engine.ingest.github_ingestor import GitHubIngestor
from greynoc_detection_engine.ingest.kev_ingestor import KEVIngestor
from greynoc_detection_engine.ingest.news_ingestor import NewsIngestor
from greynoc_detection_engine.ingest.rss_ingestor import RSSIngestor
from greynoc_detection_engine.models.source import SourceConfig, SourceType
from greynoc_detection_engine.models.threat import ThreatSeverity
from greynoc_detection_engine.scoring.ai_attack_score import AIAttackScorer
from greynoc_detection_engine.scoring.exploitability_score import ExploitabilityScorer
from greynoc_detection_engine.scoring.risk_score import RiskScorer

IngestSourceName = Literal["cve", "kev", "news", "blog", "rss", "github"]


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
        if source == "cve":
            cve_records = CVEIngestor(config, settings, fixture_path=fixture_path).ingest()
            for cve_record in cve_records:
                storage.upsert_cve(cve_record)
            result.counts["records"] += len(cve_records)
        elif source == "kev":
            kev_records = KEVIngestor(config, settings, fixture_path=fixture_path).ingest()
            for kev_record in kev_records:
                storage.upsert_kev(kev_record)
            result.counts["records"] += len(kev_records)
        elif source == "news":
            source_items = NewsIngestor(config, settings, fixture_path=fixture_path).ingest()
            for source_item in source_items:
                storage.upsert_source_item(source_item)
            result.counts["records"] += len(source_items)
        elif source == "blog":
            source_items = BlogIngestor(config, settings, fixture_path=fixture_path).ingest()
            for source_item in source_items:
                storage.upsert_source_item(source_item)
            result.counts["records"] += len(source_items)
        elif source == "rss":
            source_items = RSSIngestor(config, settings, fixture_path=fixture_path).ingest()
            for source_item in source_items:
                storage.upsert_source_item(source_item)
            result.counts["records"] += len(source_items)
        elif source == "github":
            source_items = GitHubIngestor(config, settings, fixture_path=fixture_path).ingest()
            for source_item in source_items:
                storage.upsert_source_item(source_item)
            result.counts["records"] += len(source_items)
        result.messages.append(f"Ingested {config.source_id}.")

    if not configs:
        result.status = "skipped"
        result.messages.append(f"No enabled sources configured for {source}.")
    return result


def run_correlation_job(storage: StorageBackend) -> JobResult:
    report = CorrelationEngine().correlate(
        cves=storage.list_cves(),
        kev_entries=storage.list_kev(),
        source_items=storage.list_source_items(),
    )
    library = ThreatLibrary(storage)
    for threat in report.threats:
        library.upsert(threat)
    return JobResult(
        job="correlate",
        counts={"threats": len(report.threats), "relationships": len(report.relationships)},
        messages=[relationship.reason for relationship in report.relationships[:10]],
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
    if source == "blog":
        return [
            config
            for config in registry.by_type(SourceType.RSS) + registry.by_type(SourceType.BLOG)
            if "blog" in config.tags or "research" in config.tags or "threat-intel" in config.tags
        ]
    return []
