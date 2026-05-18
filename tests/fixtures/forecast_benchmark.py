from __future__ import annotations

from datetime import timedelta

from greynoc_detector_engine.models.source import SourceItem
from greynoc_detector_engine.models.threat import ThreatRecord
from greynoc_detector_engine.utils.hashing import stable_hash
from greynoc_detector_engine.utils.time import utc_now

BENCHMARK_SIZES = (100, 1_000, 10_000)


def build_prediction_benchmark(size: int) -> tuple[list[ThreatRecord], list[SourceItem]]:
    if size not in BENCHMARK_SIZES:
        raise ValueError(f"Unsupported benchmark size: {size}")

    now = utc_now()
    threats: list[ThreatRecord] = []
    items: list[SourceItem] = []
    for idx in range(size):
        cve_id = f"CVE-2026-{idx + 10000}"
        product = f"vendor{idx % 20}:gateway{idx % 50}"
        threats.append(
            ThreatRecord(
                threat_id=f"thr-bench-{idx}",
                title=f"Benchmark threat {cve_id}",
                summary=f"Benchmark activity reported against {product}.",
                category="vulnerability",
                related_cves=[cve_id],
                affected_products=[product],
                last_seen=now,
            )
        )
        content = (
            f"Researchers mention {cve_id} with exploit availability and "
            f"defensive detection guidance for {product}."
        )
        items.append(
            SourceItem(
                item_id=f"src-bench-{idx}",
                source_id=f"bench-source-{idx % 10}",
                title=f"Benchmark report {cve_id}",
                raw_content=content,
                raw_excerpt=content,
                content_hash=stable_hash(content),
                confidence=0.85 if idx % 3 == 0 else 0.6,
                fetched_at=now - timedelta(hours=idx % 72),
                published_at=now - timedelta(hours=idx % 72),
            )
        )
    return threats, items
