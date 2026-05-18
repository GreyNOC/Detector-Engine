from __future__ import annotations

import math
from collections import Counter, defaultdict
from datetime import timedelta

from pydantic import BaseModel, ConfigDict, Field

from greynoc_detector_engine.models.source import SourceItem
from greynoc_detector_engine.utils.time import utc_now


class TrendChange(BaseModel):
    """A measured velocity delta between a long and short window."""

    model_config = ConfigDict(extra="forbid")

    key: str
    short_window_days: int
    long_window_days: int
    short_velocity: float = Field(ge=0.0)
    long_velocity: float = Field(ge=0.0)
    velocity_ratio: float
    direction: str  # "rising" | "falling" | "flat"


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

    def detect_velocity_changes(
        self,
        items: list[SourceItem],
        keys: list[str],
        *,
        short_window_days: int = 3,
        long_window_days: int = 30,
    ) -> list[TrendChange]:
        """Compute short-vs-long-window mention velocity for each key.

        A rising ratio (short > 2x long-window normalized rate) is a leading
        indicator: chatter is concentrating around the key.
        """

        now = utc_now()
        short_cutoff = now - timedelta(days=short_window_days)
        long_cutoff = now - timedelta(days=long_window_days)
        counts_short: dict[str, int] = defaultdict(int)
        counts_long: dict[str, int] = defaultdict(int)
        keys_l = [k.lower() for k in keys]

        for item in items:
            observed = item.published_at or item.fetched_at
            text = f"{item.title} {item.raw_content}".lower()
            for key in keys_l:
                if key in text:
                    if observed >= long_cutoff:
                        counts_long[key] += 1
                    if observed >= short_cutoff:
                        counts_short[key] += 1

        changes: list[TrendChange] = []
        for key in keys_l:
            short_vel = counts_short[key] / max(short_window_days, 1)
            long_vel = counts_long[key] / max(long_window_days, 1)
            ratio = (short_vel + 1e-6) / (long_vel + 1e-6)
            direction = "rising" if ratio >= 2.0 else "falling" if ratio <= 0.5 else "flat"
            changes.append(
                TrendChange(
                    key=key,
                    short_window_days=short_window_days,
                    long_window_days=long_window_days,
                    short_velocity=round(short_vel, 4),
                    long_velocity=round(long_vel, 4),
                    velocity_ratio=round(min(ratio, 100.0), 4),
                    direction=direction,
                )
            )
        return changes

    @staticmethod
    def normalized_velocity(short_velocity: float, long_velocity: float) -> float:
        """Map a short-vs-long ratio into a 0..1 score using a soft saturation."""

        ratio = (short_velocity + 1e-6) / (long_velocity + 1e-6)
        # 1 - exp(-ratio/3) gives ~0.28 at ratio=1, ~0.49 at ratio=2, ~0.86 at ratio=6
        return float(min(1.0, 1.0 - math.exp(-ratio / 3.0)))
