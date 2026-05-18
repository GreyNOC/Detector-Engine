from __future__ import annotations

import math
import re
from collections import defaultdict
from datetime import timedelta

from greynoc_detector_engine.models.prediction import PredictionSignal
from greynoc_detector_engine.models.source import SourceItem
from greynoc_detector_engine.utils.hashing import canonical_json_hash
from greynoc_detector_engine.utils.time import utc_now

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


class PredictionSignalIndex:
    """One-pass source signal index for forecast feature extraction."""

    def __init__(
        self,
        *,
        source_items: list[SourceItem],
        items_by_cve: dict[str, list[SourceItem]],
        source_ids_by_cve: dict[str, set[str]],
        trusted_counts_by_cve: dict[str, int],
        mention_counts_by_cve: dict[str, int],
        velocity_by_cve: dict[str, float],
    ) -> None:
        self.source_items = source_items
        self.items_by_cve = items_by_cve
        self.source_ids_by_cve = source_ids_by_cve
        self.trusted_counts_by_cve = trusted_counts_by_cve
        self.mention_counts_by_cve = mention_counts_by_cve
        self.velocity_by_cve = velocity_by_cve
        self.raw_items_scanned = len(source_items)

    @classmethod
    def build(
        cls,
        source_items: list[SourceItem],
        *,
        short_window_days: int = 3,
        long_window_days: int = 30,
    ) -> PredictionSignalIndex:
        now = utc_now()
        short_cutoff = now - timedelta(days=short_window_days)
        long_cutoff = now - timedelta(days=long_window_days)

        items_by_cve: dict[str, list[SourceItem]] = defaultdict(list)
        source_ids_by_cve: dict[str, set[str]] = defaultdict(set)
        trusted_counts_by_cve: dict[str, int] = defaultdict(int)
        mention_counts_by_cve: dict[str, int] = defaultdict(int)
        short_counts: dict[str, int] = defaultdict(int)
        long_counts: dict[str, int] = defaultdict(int)

        for item in source_items:
            text = f"{item.title} {item.raw_content}"
            cve_ids = {match.upper() for match in _CVE_RE.findall(text)}
            if not cve_ids:
                continue
            observed = item.published_at or item.fetched_at
            for cve_id in cve_ids:
                items_by_cve[cve_id].append(item)
                source_ids_by_cve[cve_id].add(item.source_id)
                mention_counts_by_cve[cve_id] += 1
                if item.confidence >= 0.8:
                    trusted_counts_by_cve[cve_id] += 1
                if observed >= long_cutoff:
                    long_counts[cve_id] += 1
                if observed >= short_cutoff:
                    short_counts[cve_id] += 1

        velocity_by_cve: dict[str, float] = {}
        for cve_id in mention_counts_by_cve:
            short_velocity = short_counts[cve_id] / max(short_window_days, 1)
            long_velocity = long_counts[cve_id] / max(long_window_days, 1)
            ratio = (short_velocity + 1e-6) / (long_velocity + 1e-6)
            velocity_by_cve[cve_id] = float(min(1.0, 1.0 - math.exp(-ratio / 3.0)))

        return cls(
            source_items=source_items,
            items_by_cve=dict(items_by_cve),
            source_ids_by_cve=dict(source_ids_by_cve),
            trusted_counts_by_cve=dict(trusted_counts_by_cve),
            mention_counts_by_cve=dict(mention_counts_by_cve),
            velocity_by_cve=velocity_by_cve,
        )

    def signal_for_cves(self, cve_ids: list[str]) -> PredictionSignal:
        normalized = [cve_id.upper() for cve_id in cve_ids]
        item_ids: set[str] = set()
        source_ids: set[str] = set()
        trusted = 0
        mentions = 0
        velocity = 0.0

        for cve_id in normalized:
            for item in self.items_by_cve.get(cve_id, []):
                item_ids.add(item.item_id)
            source_ids.update(self.source_ids_by_cve.get(cve_id, set()))
            trusted += self.trusted_counts_by_cve.get(cve_id, 0)
            mentions += self.mention_counts_by_cve.get(cve_id, 0)
            velocity = max(velocity, self.velocity_by_cve.get(cve_id, 0.0))

        return PredictionSignal(
            cve_ids=normalized,
            source_item_ids=sorted(item_ids),
            source_ids=sorted(source_ids),
            source_diversity=len(source_ids),
            trusted_source_count=trusted,
            cve_mention_count=mentions,
            chatter_velocity=round(velocity, 4),
            raw_items_scanned=self.raw_items_scanned,
        )

    def source_items_for_cves(self, cve_ids: list[str]) -> list[SourceItem]:
        seen: set[str] = set()
        out: list[SourceItem] = []
        for cve_id in (value.upper() for value in cve_ids):
            for item in self.items_by_cve.get(cve_id, []):
                if item.item_id in seen:
                    continue
                seen.add(item.item_id)
                out.append(item)
        return out

    @property
    def source_watermark(self) -> str:
        payload = [
            (item.item_id, item.content_hash, item.fetched_at.isoformat())
            for item in sorted(self.source_items, key=lambda value: value.item_id)
        ]
        return canonical_json_hash(payload, length=24)
