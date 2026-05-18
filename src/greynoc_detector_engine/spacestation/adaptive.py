"""Adaptive per-host scan baselines.

The fixed-threshold scan detector is great as a default, but real networks
have wildly different "normal" — a print server's normal port count is 2;
a CI runner's is 25. We learn a per-source baseline from the OS connection
table and flag anything that's a meaningful jump above that source's own
recent history.

The implementation is intentionally tiny: exponentially-weighted moving
mean + std per source-address, persisted in SQLite. Anomaly = (observed -
mean) / std >= z_threshold.
"""

from __future__ import annotations

import math
from collections import defaultdict
from datetime import datetime, timedelta

from pydantic import BaseModel, ConfigDict, Field

from greynoc_detector_engine.models.network import ConnectionRecord
from greynoc_detector_engine.utils.time import utc_now


class HostBaseline(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_address: str
    mean_distinct_ports: float = 0.0
    var_distinct_ports: float = 0.0
    sample_count: int = 0
    last_updated: datetime = Field(default_factory=utc_now)

    @property
    def stddev(self) -> float:
        return math.sqrt(max(0.0, self.var_distinct_ports))

    def z_score(self, observed: int) -> float:
        if self.sample_count < 3 or self.stddev <= 0.0:
            return 0.0 if observed <= max(2.0, self.mean_distinct_ports * 1.5) else 1.0
        return (observed - self.mean_distinct_ports) / self.stddev


class AdaptiveBaselineEngine:
    """Maintain per-source rolling mean/var of distinct local ports observed."""

    def __init__(
        self,
        *,
        alpha: float = 0.2,
        z_threshold: float = 2.5,
        baselines: dict[str, HostBaseline] | None = None,
    ) -> None:
        self.alpha = alpha  # EWMA factor (0..1; higher = more reactive)
        self.z_threshold = z_threshold
        self._baselines: dict[str, HostBaseline] = dict(baselines or {})

    # -- public --------------------------------------------------------------

    def observe(self, records: list[ConnectionRecord]) -> dict[str, int]:
        """Update baselines with the latest snapshot; return distinct-port counts."""
        ports_per_source = self._distinct_ports_by_source(records)
        for source, count in ports_per_source.items():
            self._update_one(source, count)
        return ports_per_source

    def is_anomalous(self, source: str, observed: int) -> tuple[bool, float, HostBaseline]:
        baseline = self._baselines.get(source) or HostBaseline(source_address=source)
        z = baseline.z_score(observed)
        # Always require at least a small absolute floor so a "0 mean, 1 observed"
        # source doesn't blow up the z-score numerator.
        if observed < 3 and baseline.sample_count == 0:
            return False, z, baseline
        return z >= self.z_threshold, z, baseline

    def baselines(self) -> list[HostBaseline]:
        return list(self._baselines.values())

    def load(self, baselines: list[HostBaseline]) -> None:
        for b in baselines:
            self._baselines[b.source_address] = b

    def decay_stale(self, *, older_than_days: int = 30) -> int:
        """Remove baselines we haven't seen in a long time. Returns # removed."""
        cutoff = utc_now() - timedelta(days=older_than_days)
        stale = [s for s, b in self._baselines.items() if b.last_updated < cutoff]
        for s in stale:
            self._baselines.pop(s, None)
        return len(stale)

    # -- internals -----------------------------------------------------------

    @staticmethod
    def _distinct_ports_by_source(records: list[ConnectionRecord]) -> dict[str, int]:
        ports: dict[str, set[int]] = defaultdict(set)
        for r in records:
            if r.remote_address in {"", "0.0.0.0", "::", "*"}:
                continue
            ports[r.remote_address].add(r.local_port)
        return {s: len(p) for s, p in ports.items()}

    def _update_one(self, source: str, observed: int) -> None:
        baseline = self._baselines.get(source) or HostBaseline(source_address=source)
        old_mean = baseline.mean_distinct_ports
        # Welford-style EWMA mean + EWMA variance
        new_mean = (1 - self.alpha) * old_mean + self.alpha * observed
        new_var = (1 - self.alpha) * (
            baseline.var_distinct_ports + self.alpha * (observed - old_mean) ** 2
        )
        self._baselines[source] = baseline.model_copy(
            update={
                "mean_distinct_ports": new_mean,
                "var_distinct_ports": new_var,
                "sample_count": baseline.sample_count + 1,
                "last_updated": utc_now(),
            }
        )
