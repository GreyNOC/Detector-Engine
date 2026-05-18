from __future__ import annotations

from collections import Counter
from datetime import timedelta

from greynoc_detector_engine.models.source import SourceItem
from greynoc_detector_engine.utils.time import utc_now


class TrendEngine:
    def source_frequency(self, items: list[SourceItem], *, window_days: int = 7) -> dict[str, int]:
        cutoff = utc_now() - timedelta(days=window_days)
        counter: Counter[str] = Counter()
        for item in items:
            observed_at = item.published_at or item.fetched_at
            if observed_at >= cutoff:
                counter[item.source_id] += 1
        return dict(counter)

    def term_frequency(self, items: list[SourceItem], terms: list[str]) -> dict[str, int]:
        counter: Counter[str] = Counter()
        for item in items:
            text = f"{item.title} {item.raw_content}".lower()
            for term in terms:
                if term.lower() in text:
                    counter[term] += 1
        return dict(counter)
