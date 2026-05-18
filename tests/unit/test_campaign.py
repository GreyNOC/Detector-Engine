from __future__ import annotations

from datetime import timedelta

from greynoc_detector_engine.analysis.campaign import CampaignClusterer
from greynoc_detector_engine.models.threat import ThreatRecord
from greynoc_detector_engine.utils.time import utc_now


def _threat(threat_id: str, *, cves: list[str], products: list[str], days_ago: int) -> ThreatRecord:
    return ThreatRecord(
        threat_id=threat_id,
        title=f"Threat {threat_id}",
        summary="LockBit ransomware activity reported by Mandiant.",
        category="vulnerability",
        related_cves=cves,
        affected_products=products,
        first_seen=utc_now() - timedelta(days=days_ago),
        last_seen=utc_now() - timedelta(days=max(0, days_ago - 1)),
    )


def test_campaign_clusters_by_shared_actor_and_product() -> None:
    threats = [
        _threat("thr-a", cves=["CVE-2026-12345"], products=["fortinet:fortios"], days_ago=2),
        _threat("thr-b", cves=["CVE-2026-12345"], products=["fortinet:fortios"], days_ago=5),
        _threat("thr-c", cves=["CVE-2024-99999"], products=["unrelated:product"], days_ago=200),
    ]
    clusters = CampaignClusterer().cluster(threats, source_items=[])
    # Two of the threats share CVE + product + actor name in summary; the
    # third does not.
    assigned = {tid for c in clusters for tid in c.related_threat_ids}
    assert "thr-a" in assigned and "thr-b" in assigned
    primary = next(c for c in clusters if "thr-a" in c.related_threat_ids)
    assert "thr-b" in primary.related_threat_ids
    assert primary.cohesion > 0


def test_campaign_marks_unrelated_threats_as_separate_clusters() -> None:
    threats = [
        _threat("thr-a", cves=["CVE-2026-1"], products=["vendor:one"], days_ago=1),
        _threat("thr-b", cves=["CVE-2024-2"], products=["vendor:two"], days_ago=200),
    ]
    clusters = CampaignClusterer().cluster(threats, source_items=[])
    cluster_ids = {c.campaign_id for c in clusters}
    assert len(cluster_ids) == 2
