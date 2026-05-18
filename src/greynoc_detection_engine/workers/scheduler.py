from __future__ import annotations

from apscheduler.schedulers.background import BackgroundScheduler

from greynoc_detection_engine.config.settings import Settings
from greynoc_detection_engine.workers.jobs import build_storage, run_correlation_job, run_ingest_job


def build_scheduler(settings: Settings) -> BackgroundScheduler:
    storage = build_storage(settings)
    scheduler = BackgroundScheduler(timezone="UTC")
    scheduler.add_job(
        lambda: run_ingest_job(source="cve", settings=settings, storage=storage),
        trigger="interval",
        hours=6,
        id="ingest-cve",
        replace_existing=True,
    )
    scheduler.add_job(
        lambda: run_ingest_job(source="kev", settings=settings, storage=storage),
        trigger="interval",
        hours=6,
        id="ingest-kev",
        replace_existing=True,
    )
    scheduler.add_job(
        lambda: run_correlation_job(storage),
        trigger="interval",
        hours=1,
        id="correlate",
        replace_existing=True,
    )
    return scheduler
