from __future__ import annotations

import math
from collections import Counter, defaultdict
from collections.abc import Callable
from datetime import datetime, timedelta

from greynoc_detector_engine.models.prediction import VelocityBaseline
from greynoc_detector_engine.models.source import SourceItem
from greynoc_detector_engine.normalize.entity_extractor import EntityExtractor
from greynoc_detector_engine.utils.time import utc_now

KeyExtractor = Callable[[str], list[str]]


class VelocityBaselineEngine:
    """Detect anomalous chatter for any keyed signal (CVE, product, term).

    Without ML deps we use a rolling mean + sample std-dev with daily buckets
    and emit a z-score. An anomaly is anything > 2.5 sigma over the prior
    `window_days` baseline. This catches the run-up that precedes most public
    exploitation events (PoC drop → patch reverse-engineering chatter → mass
    scanning).
    """

    def __init__(self, *, window_days: int = 30, anomaly_z: float = 2.5) -> None:
        self.window_days = window_days
        self.anomaly_z = anomaly_z
        self._extractor = EntityExtractor()

    def baselines_for_cves(self, items: list[SourceItem]) -> list[VelocityBaseline]:
        bucketed = self._bucket_keys(
            items,
            lambda text: self._extractor.extract(text).cve_ids,
        )
        return self._build_baselines(bucketed)

    def baselines_for_products(
        self, items: list[SourceItem], products: list[str]
    ) -> list[VelocityBaseline]:
        products_l = [p.lower() for p in products]

        def extract(text: str) -> list[str]:
            t = text.lower()
            return [p for p in products_l if p in t]

        bucketed = self._bucket_keys(items, extract)
        return self._build_baselines(bucketed)

    def baselines_for_terms(
        self, items: list[SourceItem], terms: list[str]
    ) -> list[VelocityBaseline]:
        terms_l = [t.lower() for t in terms]

        def extract(text: str) -> list[str]:
            t = text.lower()
            return [term for term in terms_l if term in t]

        bucketed = self._bucket_keys(items, extract)
        return self._build_baselines(bucketed)

    def _bucket_keys(
        self,
        items: list[SourceItem],
        extract_keys: KeyExtractor,
    ) -> dict[str, dict[str, int]]:
        bucketed: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for item in items:
            observed = item.published_at or item.fetched_at
            bucket = observed.date().isoformat()
            text = f"{item.title} {item.raw_content}"
            for key in extract_keys(text):
                bucketed[key][bucket] += 1
        return bucketed

    def _build_baselines(self, bucketed: dict[str, dict[str, int]]) -> list[VelocityBaseline]:
        now = utc_now()
        latest_bucket = now.date().isoformat()
        baseline_start = (now - timedelta(days=self.window_days)).date().isoformat()
        baselines: list[VelocityBaseline] = []
        for key, daily in bucketed.items():
            observed_today = daily.get(latest_bucket, 0)
            history_counts = [
                count for day, count in daily.items() if baseline_start <= day < latest_bucket
            ]
            if not history_counts:
                history_counts = [0]
            mean = sum(history_counts) / len(history_counts)
            variance = (
                sum((c - mean) ** 2 for c in history_counts) / len(history_counts)
                if len(history_counts) > 1
                else 0.0
            )
            std = math.sqrt(variance)
            z = (observed_today - mean) / std if std > 0 else (observed_today - mean)
            baselines.append(
                VelocityBaseline(
                    key=key,
                    window_days=self.window_days,
                    baseline_mean=round(mean, 3),
                    baseline_std=round(std, 3),
                    observed=observed_today,
                    z_score=round(z, 3),
                    is_anomalous=z >= self.anomaly_z and observed_today > 0,
                )
            )
        return baselines

    @staticmethod
    def hot_keys(baselines: list[VelocityBaseline]) -> list[str]:
        return [b.key for b in baselines if b.is_anomalous]


class ChatterIndex:
    """Lightweight in-memory aggregate of who-mentions-what, used by the engine."""

    def __init__(self) -> None:
        self.by_cve: Counter[str] = Counter()
        self.by_product: Counter[str] = Counter()
        self.by_actor: Counter[str] = Counter()
        self.by_term: Counter[str] = Counter()
        self.last_seen: dict[str, datetime] = {}

    def ingest(self, item: SourceItem) -> None:
        text = f"{item.title} {item.raw_content}"
        ent = EntityExtractor().extract(text)
        for cve in ent.cve_ids:
            self.by_cve[cve] += 1
            self.last_seen[cve] = item.published_at or item.fetched_at
        for product in ent.products:
            self.by_product[product.lower()] += 1
        for term in ent.ai_terms + ent.exploit_terms:
            self.by_term[term] += 1
