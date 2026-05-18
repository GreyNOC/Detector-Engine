from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from uuid import uuid4

from greynoc_detector_engine.enrich.threat_actor import ThreatActorAttributor
from greynoc_detector_engine.models.prediction import CampaignCluster
from greynoc_detector_engine.models.source import SourceItem
from greynoc_detector_engine.models.threat import ThreatRecord


class CampaignClusterer:
    """Cluster threat records into inferred campaigns.

    The signal-of-record for "this looks like one campaign" is overlap on
    *any two* of: shared actor, shared CVE, shared affected-product, and
    temporal proximity (< 21 days between first/last-seen). The clusters are
    explicit and explainable — no opaque ML embeddings.
    """

    def __init__(self, *, proximity_days: int = 21) -> None:
        self.proximity_days = proximity_days
        self.attributor = ThreatActorAttributor()

    def cluster(
        self,
        threats: list[ThreatRecord],
        source_items: list[SourceItem],
    ) -> list[CampaignCluster]:
        if not threats:
            return []
        actor_index = self._actor_index_for_threats(threats, source_items)
        clusters: list[CampaignCluster] = []
        assigned: dict[str, str] = {}

        for threat in threats:
            existing_id = self._match_existing(threat, clusters, actor_index)
            if existing_id is None:
                cluster = self._seed_cluster(threat, actor_index)
                clusters.append(cluster)
                existing_id = cluster.campaign_id
            else:
                self._merge_into(existing_id, threat, clusters, actor_index)
            assigned[threat.threat_id] = existing_id

        for cluster in clusters:
            self._finalize(cluster)
        return clusters

    def _actor_index_for_threats(
        self,
        threats: list[ThreatRecord],
        items: list[SourceItem],
    ) -> dict[str, list[str]]:
        # threat_id -> [actor_id]
        text_by_threat: dict[str, list[str]] = defaultdict(list)
        for threat in threats:
            text_by_threat[threat.threat_id].append(threat.title + " " + threat.summary)
        cve_to_threat = {cve: t.threat_id for t in threats for cve in t.related_cves}
        for item in items:
            text = f"{item.title} {item.raw_content}"
            for cve, tid in cve_to_threat.items():
                if cve.lower() in text.lower():
                    text_by_threat[tid].append(text)
        out: dict[str, list[str]] = {}
        for tid, blobs in text_by_threat.items():
            actors = self.attributor.actor_ids(" ".join(blobs))
            if actors:
                out[tid] = actors
        return out

    def _seed_cluster(
        self,
        threat: ThreatRecord,
        actor_index: dict[str, list[str]],
    ) -> CampaignCluster:
        actors = actor_index.get(threat.threat_id, [])
        label_parts: list[str] = []
        if actors:
            label_parts.append(actors[0])
        if threat.affected_products:
            label_parts.append(threat.affected_products[0])
        if not label_parts:
            label_parts.append(threat.category)
        label = " / ".join(label_parts) + " campaign"
        return CampaignCluster(
            campaign_id=f"camp-{uuid4().hex[:10]}",
            label=label,
            related_threat_ids=[threat.threat_id],
            related_cves=list(threat.related_cves),
            suspected_actors=list(actors),
            shared_indicators=[i.value for i in threat.observed_indicators],
            affected_products=list(threat.affected_products),
            first_seen=threat.first_seen,
            last_seen=threat.last_seen,
            reasons=[f"Seeded cluster from threat {threat.threat_id}."],
        )

    def _match_existing(
        self,
        threat: ThreatRecord,
        clusters: list[CampaignCluster],
        actor_index: dict[str, list[str]],
    ) -> str | None:
        actors = set(actor_index.get(threat.threat_id, []))
        threat_cves = set(threat.related_cves)
        threat_products = {p.lower() for p in threat.affected_products}

        for cluster in clusters:
            score = 0
            shared_actors = actors & set(cluster.suspected_actors)
            shared_cves = threat_cves & set(cluster.related_cves)
            shared_products = threat_products & {p.lower() for p in cluster.affected_products}
            if shared_actors:
                score += 2
            if shared_cves:
                score += 2
            if shared_products:
                score += 1
            if self._temporally_proximate(threat, cluster):
                score += 1
            if score >= 3:
                return cluster.campaign_id
        return None

    def _temporally_proximate(
        self,
        threat: ThreatRecord,
        cluster: CampaignCluster,
    ) -> bool:
        a = threat.first_seen or threat.last_seen
        b = cluster.last_seen or cluster.first_seen
        if a is None or b is None:
            return False
        return abs((a - b).days) <= self.proximity_days

    def _merge_into(
        self,
        cluster_id: str,
        threat: ThreatRecord,
        clusters: list[CampaignCluster],
        actor_index: dict[str, list[str]],
    ) -> None:
        cluster = next(c for c in clusters if c.campaign_id == cluster_id)
        cluster.related_threat_ids = sorted({*cluster.related_threat_ids, threat.threat_id})
        cluster.related_cves = sorted({*cluster.related_cves, *threat.related_cves})
        cluster.suspected_actors = sorted(
            {*cluster.suspected_actors, *actor_index.get(threat.threat_id, [])}
        )
        cluster.affected_products = sorted({*cluster.affected_products, *threat.affected_products})
        cluster.shared_indicators = sorted(
            {*cluster.shared_indicators, *(i.value for i in threat.observed_indicators)}
        )
        cluster.first_seen = self._min_date(cluster.first_seen, threat.first_seen)
        cluster.last_seen = self._max_date(cluster.last_seen, threat.last_seen)
        cluster.reasons.append(f"Merged threat {threat.threat_id} into cluster on shared signals.")

    @staticmethod
    def _min_date(a: datetime | None, b: datetime | None) -> datetime | None:
        if a is None:
            return b
        if b is None:
            return a
        return min(a, b)

    @staticmethod
    def _max_date(a: datetime | None, b: datetime | None) -> datetime | None:
        if a is None:
            return b
        if b is None:
            return a
        return max(a, b)

    def _finalize(self, cluster: CampaignCluster) -> None:
        # Velocity: threats per day across the cluster span
        span = self._span_days(cluster)
        velocity = min(1.0, len(cluster.related_threat_ids) / max(span, 1) / 2.0)

        # Cohesion: fraction of cluster signals that are *shared*, not unique
        cohesion_components = [
            1.0 if cluster.suspected_actors else 0.0,
            1.0 if cluster.related_cves else 0.0,
            1.0 if cluster.affected_products else 0.0,
            1.0 if cluster.shared_indicators else 0.0,
        ]
        cohesion = sum(cohesion_components) / len(cohesion_components)

        cluster.velocity_score = round(velocity, 3)
        cluster.cohesion = round(cohesion, 3)

    @staticmethod
    def _span_days(cluster: CampaignCluster) -> int:
        if cluster.first_seen and cluster.last_seen:
            delta = cluster.last_seen - cluster.first_seen
            return max(1, delta.days)
        return 1

    @staticmethod
    def is_active(cluster: CampaignCluster, *, within_days: int = 14) -> bool:
        if cluster.last_seen is None:
            return False
        return (datetime.now(cluster.last_seen.tzinfo) - cluster.last_seen) <= timedelta(
            days=within_days
        )
