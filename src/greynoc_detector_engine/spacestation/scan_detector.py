"""Detect scanning / probing patterns in a connection-table snapshot stream.

Heuristics (all explainable, all configurable):

  * Port scan         — one remote address touches N >= distinct_port_threshold
                        distinct local ports within window_seconds.
  * Slow scan         — same as above but with a longer window and lower
                        threshold to catch low-and-slow recon.
  * SYN flood         — a remote address with many SYN_SENT/SYN_RECV-ish
                        states against one local port.
  * Port knock        — N >= knock_min hits on distinct, ordered ports from
                        the same remote inside knock_window_seconds.
  * ICS probe         — any inbound touch on a known ICS port.
  * Darknet touch     — any inbound touch on a configured "should-never-be-
                        contacted" port.

No state is shared with the remote: we only read the OS table.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from datetime import timedelta
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from greynoc_detector_engine.ics.protocols import ICS_PORTS
from greynoc_detector_engine.models.network import (
    ConnectionRecord,
    IntrusionKind,
    IntrusionSeverity,
    IntrusionSignal,
)
from greynoc_detector_engine.utils.time import utc_now


class ScanDetectionConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fast_port_threshold: int = Field(default=8, ge=2)
    fast_window_seconds: int = Field(default=60, ge=1)
    slow_port_threshold: int = Field(default=4, ge=2)
    slow_window_seconds: int = Field(default=3600, ge=60)
    syn_flood_threshold: int = Field(default=25, ge=5)
    knock_min: int = Field(default=3, ge=2)
    knock_window_seconds: int = Field(default=30, ge=1)
    darknet_ports: list[int] = Field(default_factory=list)
    treat_ics_inbound_as_signal: bool = True
    exclude_loopback: bool = True
    exclude_multicast: bool = True
    exclude_link_local: bool = True
    exclude_addresses: list[str] = Field(default_factory=list)


class ScanDetector:
    """Stateless evaluator over a batch of ConnectionRecord snapshots."""

    def __init__(self, config: ScanDetectionConfig | None = None) -> None:
        self.config = config or ScanDetectionConfig()

    def detect(self, records: list[ConnectionRecord]) -> list[IntrusionSignal]:
        signals: list[IntrusionSignal] = []
        signals.extend(self._detect_port_scans(records))
        signals.extend(self._detect_syn_floods(records))
        signals.extend(self._detect_port_knocks(records))
        signals.extend(self._detect_ics_inbound(records))
        signals.extend(self._detect_darknet_touches(records))
        return signals

    # -- detectors -----------------------------------------------------------

    def _detect_port_scans(self, records: list[ConnectionRecord]) -> list[IntrusionSignal]:
        # Group inbound attempts by (remote_address) -> set of local ports touched
        ports_by_source: dict[str, dict[int, ConnectionRecord]] = defaultdict(dict)
        for r in records:
            if not self._is_inbound_attempt(r):
                continue
            ports_by_source[r.remote_address].setdefault(r.local_port, r)

        signals: list[IntrusionSignal] = []
        for source, port_map in ports_by_source.items():
            ports = sorted(port_map)
            if len(ports) >= self.config.fast_port_threshold:
                anchors = list(port_map.values())
                signals.append(
                    IntrusionSignal(
                        signal_id=f"scan-{uuid4().hex[:10]}",
                        kind=IntrusionKind.PORT_SCAN,
                        severity=IntrusionSeverity.HIGH,
                        source_address=source,
                        target_ports=ports,
                        target_addresses=sorted({r.local_address for r in anchors}),
                        observation_count=len(ports),
                        window_seconds=float(self.config.fast_window_seconds),
                        confidence=0.85,
                        first_seen=min(r.observed_at for r in anchors),
                        last_seen=max(r.observed_at for r in anchors),
                        reasons=[
                            f"{len(ports)} distinct local ports touched from "
                            f"{source} within the fast window."
                        ],
                    )
                )
            elif len(ports) >= self.config.slow_port_threshold:
                anchors = list(port_map.values())
                window = max(
                    timedelta(seconds=1),
                    max(r.observed_at for r in anchors) - min(r.observed_at for r in anchors),
                )
                if window <= timedelta(seconds=self.config.slow_window_seconds):
                    signals.append(
                        IntrusionSignal(
                            signal_id=f"slow-{uuid4().hex[:10]}",
                            kind=IntrusionKind.SLOW_SCAN,
                            severity=IntrusionSeverity.MEDIUM,
                            source_address=source,
                            target_ports=ports,
                            target_addresses=sorted({r.local_address for r in anchors}),
                            observation_count=len(ports),
                            window_seconds=window.total_seconds(),
                            confidence=0.6,
                            first_seen=min(r.observed_at for r in anchors),
                            last_seen=max(r.observed_at for r in anchors),
                            reasons=[
                                f"{len(ports)} distinct ports over "
                                f"{window.total_seconds():.0f}s — low-and-slow pattern."
                            ],
                        )
                    )
        return signals

    def _detect_syn_floods(self, records: list[ConnectionRecord]) -> list[IntrusionSignal]:
        # Many half-open states from one source against one port.
        counter: dict[tuple[str, str, int], list[ConnectionRecord]] = defaultdict(list)
        for r in records:
            if r.state in {"SYN_SENT", "SYN_RECV", "SYN-RECEIVED"}:
                counter[(r.remote_address, r.local_address, r.local_port)].append(r)
        signals: list[IntrusionSignal] = []
        for (source, dst, port), hits in counter.items():
            if len(hits) < self.config.syn_flood_threshold:
                continue
            signals.append(
                IntrusionSignal(
                    signal_id=f"synflood-{uuid4().hex[:10]}",
                    kind=IntrusionKind.SYN_FLOOD,
                    severity=IntrusionSeverity.CRITICAL,
                    source_address=source,
                    target_addresses=[dst],
                    target_ports=[port],
                    observation_count=len(hits),
                    confidence=0.9,
                    first_seen=min(r.observed_at for r in hits),
                    last_seen=max(r.observed_at for r in hits),
                    reasons=[f"{len(hits)} half-open states from {source} to {dst}:{port}."],
                )
            )
        return signals

    def _detect_port_knocks(self, records: list[ConnectionRecord]) -> list[IntrusionSignal]:
        # Ordered sequence of distinct ports from same source within window.
        by_source: dict[str, list[ConnectionRecord]] = defaultdict(list)
        for r in records:
            if self._is_inbound_attempt(r):
                by_source[r.remote_address].append(r)
        signals: list[IntrusionSignal] = []
        for source, hits in by_source.items():
            ordered = sorted(hits, key=lambda r: r.observed_at)
            window_start = 0
            for end in range(len(ordered)):
                while (
                    ordered[end].observed_at - ordered[window_start].observed_at
                ).total_seconds() > self.config.knock_window_seconds:
                    window_start += 1
                ports_in_window = {ordered[i].local_port for i in range(window_start, end + 1)}
                if len(ports_in_window) >= self.config.knock_min and 2 <= len(ports_in_window) <= 8:
                    window_records = ordered[window_start : end + 1]
                    signals.append(
                        IntrusionSignal(
                            signal_id=f"knock-{uuid4().hex[:10]}",
                            kind=IntrusionKind.PORT_KNOCK,
                            severity=IntrusionSeverity.MEDIUM,
                            source_address=source,
                            target_ports=sorted(ports_in_window),
                            target_addresses=sorted({r.local_address for r in window_records}),
                            observation_count=len(window_records),
                            window_seconds=float(self.config.knock_window_seconds),
                            confidence=0.55,
                            first_seen=window_records[0].observed_at,
                            last_seen=window_records[-1].observed_at,
                            reasons=[
                                f"{len(ports_in_window)} distinct ports knocked from "
                                f"{source} within {self.config.knock_window_seconds}s."
                            ],
                        )
                    )
                    break  # one knock signal per source per batch
        return signals

    def _detect_ics_inbound(self, records: list[ConnectionRecord]) -> list[IntrusionSignal]:
        if not self.config.treat_ics_inbound_as_signal:
            return []
        signals: list[IntrusionSignal] = []
        for r in records:
            if not self._is_inbound_attempt(r):
                continue
            if r.local_port not in ICS_PORTS:
                continue
            signals.append(
                IntrusionSignal(
                    signal_id=f"ics-{uuid4().hex[:10]}",
                    kind=IntrusionKind.ICS_PROBE,
                    severity=IntrusionSeverity.HIGH,
                    source_address=r.remote_address,
                    target_addresses=[r.local_address],
                    target_ports=[r.local_port],
                    observation_count=1,
                    confidence=0.8,
                    first_seen=r.observed_at,
                    last_seen=r.observed_at,
                    reasons=[
                        f"Inbound attempt against ICS port {r.local_port} "
                        f"(state {r.state}) from {r.remote_address}."
                    ],
                )
            )
        return signals

    def _detect_darknet_touches(self, records: list[ConnectionRecord]) -> list[IntrusionSignal]:
        if not self.config.darknet_ports:
            return []
        signals: list[IntrusionSignal] = []
        for r in records:
            if not self._is_inbound_attempt(r):
                continue
            if r.local_port not in set(self.config.darknet_ports):
                continue
            signals.append(
                IntrusionSignal(
                    signal_id=f"darknet-{uuid4().hex[:10]}",
                    kind=IntrusionKind.DARKNET_TOUCH,
                    severity=IntrusionSeverity.CRITICAL,
                    source_address=r.remote_address,
                    target_addresses=[r.local_address],
                    target_ports=[r.local_port],
                    observation_count=1,
                    confidence=0.95,
                    first_seen=r.observed_at,
                    last_seen=r.observed_at or utc_now(),
                    reasons=[
                        f"Touch on darknet port {r.local_port} from {r.remote_address} "
                        "(no legitimate service exists on this port)."
                    ],
                )
            )
        return signals

    # -- helpers -------------------------------------------------------------

    def _is_inbound_attempt(self, record: ConnectionRecord) -> bool:
        # LISTEN rows have remote_address == "0.0.0.0"/"::" and remote_port == 0;
        # we explicitly exclude them and any state we know isn't an active probe.
        if record.remote_address in {"", "0.0.0.0", "::", "*"}:
            return False
        if record.remote_port == 0:
            return False
        if record.state.upper() in {"LISTEN", "LISTENING", "CLOSE_WAIT"}:
            return False
        # Exclusion sets: by default we treat loopback/multicast/link-local as
        # not-scans because they generate enormous false-positive volume on
        # any normal host.
        if record.remote_address in set(self.config.exclude_addresses):
            return False
        try:
            ip = ipaddress.ip_address(record.remote_address)
        except ValueError:
            return True
        if self.config.exclude_loopback and ip.is_loopback:
            return False
        if self.config.exclude_multicast and ip.is_multicast:
            return False
        return not (self.config.exclude_link_local and ip.is_link_local)
