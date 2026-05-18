"""Wire the network/ICS/spacestation modules into the engine pipeline.

The orchestrator is invoked by the CLI/API. It:

  1. Runs PassiveDiscovery, persists NetworkDevice rows.
  2. Runs ICSDeviceClassifier, persists ICSObservation rows, retags devices.
  3. Reads the connection-table sensor and runs ScanDetector.
  4. Persists IntrusionSignal rows.
  5. Bridges discovered devices into the AssetInventory and predictive layer.
  6. For high-severity scan signals, creates a synthetic ThreatRecord so the
     predictive engine can surface the live intrusion alongside CVE-based
     threats.
"""

from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from greynoc_detector_engine.ics.classifier import ICSDeviceClassifier
from greynoc_detector_engine.models.indicator import Indicator, IndicatorType
from greynoc_detector_engine.models.network import (
    IntrusionSeverity,
    IntrusionSignal,
    NetworkDevice,
)
from greynoc_detector_engine.models.source import SourceReference
from greynoc_detector_engine.models.threat import (
    ThreatRecord,
    ThreatSeverity,
    ThreatStatus,
)
from greynoc_detector_engine.network.discovery import PassiveDiscovery
from greynoc_detector_engine.network.inventory_bridge import assets_from_devices
from greynoc_detector_engine.spacestation.scan_detector import (
    ScanDetectionConfig,
    ScanDetector,
)
from greynoc_detector_engine.spacestation.sensor import (
    ConnectionTableSensor,
    listening_ports,
)
from greynoc_detector_engine.storage.base import StorageBackend
from greynoc_detector_engine.utils.hashing import stable_hash
from greynoc_detector_engine.utils.time import utc_now


class SensorRunResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    job: str = "sensor:run"
    status: str = "ok"
    counts: dict[str, int] = Field(default_factory=dict)
    messages: list[str] = Field(default_factory=list)


def run_discovery_job(
    storage: StorageBackend,
    *,
    discovery: PassiveDiscovery | None = None,
) -> SensorRunResult:
    discovery = discovery or PassiveDiscovery()
    devices = discovery.discover()
    return _persist_discovery(storage, devices, job_label="sensor:discover")


def run_sensor_job(
    storage: StorageBackend,
    *,
    discovery: PassiveDiscovery | None = None,
    sensor: ConnectionTableSensor | None = None,
    detector: ScanDetector | None = None,
    scan_config: ScanDetectionConfig | None = None,
) -> SensorRunResult:
    discovery = discovery or PassiveDiscovery()
    sensor = sensor or ConnectionTableSensor()
    detector = detector or ScanDetector(scan_config)

    devices = discovery.discover()
    records = sensor.snapshot()
    listening = listening_ports(records)
    devices = _annotate_devices_with_listening_ports(devices, listening)
    devices, observations = ICSDeviceClassifier().classify(devices)

    for device in devices:
        storage.upsert_network_device(device)
    for observation in observations:
        storage.record_ics_observation(observation)
    for asset in assets_from_devices(devices):
        storage.upsert_asset(asset)

    signals = detector.detect(records)
    for signal in signals:
        storage.upsert_intrusion_signal(signal)

    threats_created = _materialize_threats_from_signals(storage, signals)

    return SensorRunResult(
        counts={
            "devices": len(devices),
            "ics_observations": len(observations),
            "connection_records": len(records),
            "intrusion_signals": len(signals),
            "threats_materialized": threats_created,
        },
        messages=[f"{s.kind.value} from {s.source_address}" for s in signals[:10]],
    )


def local_intrusion_pressure(
    storage: StorageBackend,
    *,
    window_minutes: int = 60,
) -> float:
    """Aggregate recent intrusion signals into a [0, 1] feature value.

    Recent signals weigh more than old ones; CRITICAL/HIGH weigh more than
    MEDIUM/LOW. Used as a predictive feature.
    """
    cutoff = utc_now() - timedelta(minutes=window_minutes)
    weight = 0.0
    severity_weight = {
        IntrusionSeverity.CRITICAL: 1.0,
        IntrusionSeverity.HIGH: 0.7,
        IntrusionSeverity.MEDIUM: 0.35,
        IntrusionSeverity.LOW: 0.1,
        IntrusionSeverity.INFO: 0.05,
    }
    for signal in storage.list_intrusion_signals():
        if signal.last_seen < cutoff:
            continue
        weight = max(weight, severity_weight[signal.severity])
    return min(1.0, weight)


# -- helpers ------------------------------------------------------------------


def _persist_discovery(
    storage: StorageBackend,
    devices: list[NetworkDevice],
    *,
    job_label: str,
) -> SensorRunResult:
    devices, observations = ICSDeviceClassifier().classify(devices)
    for device in devices:
        storage.upsert_network_device(device)
    for observation in observations:
        storage.record_ics_observation(observation)
    for asset in assets_from_devices(devices):
        storage.upsert_asset(asset)
    return SensorRunResult(
        job=job_label,
        counts={"devices": len(devices), "ics_observations": len(observations)},
    )


def _annotate_devices_with_listening_ports(
    devices: list[NetworkDevice], ports: set[int]
) -> list[NetworkDevice]:
    if not ports:
        return devices
    out: list[NetworkDevice] = []
    for device in devices:
        merged_ports = sorted(set(device.observed_ports) | ports)
        if merged_ports != device.observed_ports:
            out.append(device.model_copy(update={"observed_ports": merged_ports}))
        else:
            out.append(device)
    return out


_HIGH_SEVERITIES = {IntrusionSeverity.CRITICAL, IntrusionSeverity.HIGH}


def _materialize_threats_from_signals(
    storage: StorageBackend, signals: list[IntrusionSignal]
) -> int:
    created = 0
    for signal in signals:
        if signal.severity not in _HIGH_SEVERITIES:
            continue
        threat = _signal_to_threat(signal)
        existing = storage.get_threat(threat.threat_id)
        if existing is None:
            storage.upsert_threat(threat)
            created += 1
        else:
            merged = existing.model_copy(
                update={
                    "last_seen": signal.last_seen,
                    "changelog": [
                        *existing.changelog,
                        f"Refreshed by live sensor signal {signal.signal_id}.",
                    ],
                }
            )
            storage.upsert_threat(merged)
    return created


def _signal_to_threat(signal: IntrusionSignal) -> ThreatRecord:
    """Convert an intrusion signal into a structured ThreatRecord for the library."""
    threat_id = f"thr-sensor-{stable_hash(signal.source_address + signal.kind.value)}"
    indicators = [
        Indicator(
            value=signal.source_address,
            type=IndicatorType.IPV4,
            confidence=signal.confidence,
            source="spacestation_sensor",
        )
    ]
    severity_map = {
        IntrusionSeverity.CRITICAL: ThreatSeverity.CRITICAL,
        IntrusionSeverity.HIGH: ThreatSeverity.HIGH,
        IntrusionSeverity.MEDIUM: ThreatSeverity.MEDIUM,
        IntrusionSeverity.LOW: ThreatSeverity.LOW,
        IntrusionSeverity.INFO: ThreatSeverity.LOW,
    }
    return ThreatRecord(
        threat_id=threat_id,
        title=f"Live {signal.kind.value.replace('_', ' ')} from {signal.source_address}",
        summary=("Detected by the spacestation sensor: " + "; ".join(signal.reasons[:3]) + "."),
        category="live_intrusion",
        observed_indicators=indicators,
        confidence=signal.confidence,
        severity=severity_map[signal.severity],
        source_references=[
            SourceReference(
                title=f"Spacestation sensor signal {signal.signal_id}",
                source="spacestation_sensor",
                content_hash=stable_hash(signal.signal_id),
                confidence=signal.confidence,
                raw_excerpt=" | ".join(signal.reasons),
            )
        ],
        first_seen=signal.first_seen,
        last_seen=signal.last_seen,
        recommended_soc_actions=[
            f"Investigate source IP {signal.source_address} immediately.",
            "Correlate with firewall/IDS logs; block at perimeter if confirmed.",
            (
                "If targets include ICS ports, contact the OT engineering owner before "
                "any mitigation that could affect process safety."
            ),
        ],
        status=ThreatStatus.NEW,
        changelog=[f"Created by spacestation sensor from {signal.signal_id}."],
    )


def fingerprint_for_signal(signal: IntrusionSignal) -> str:
    """Stable id used to dedupe synthetic threats from repeat signals."""
    return f"sensor-{uuid4().hex[:8]}-{signal.source_address}-{signal.kind.value}"
