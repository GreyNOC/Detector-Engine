"""Classify network devices as ICS assets from passive signals only.

Inputs: NetworkDevice records (with MAC OUI + observed listening ports).
Outputs: enriched NetworkDevice + per-device ICSObservation records.

We never probe an ICS protocol to confirm. If a device looks like a PLC,
we *suspect* a PLC and tag it; an operator confirms.
"""

from __future__ import annotations

from typing import ClassVar

from greynoc_detector_engine.ics.protocols import ICS_PORT_REGISTRY, protocol_for_port
from greynoc_detector_engine.models.network import (
    DeviceRole,
    ICSObservation,
    NetworkDevice,
)


class ICSDeviceClassifier:
    """Tag devices that exhibit ICS protocol signatures."""

    _OT_VENDOR_HINTS = (
        "rockwell",
        "allen-bradley",
        "siemens",
        "schneider",
        "honeywell",
        "omron",
        "mitsubishi",
        "yokogawa",
        "ge industrial",
        "beckhoff",
        "phoenix contact",
        "endress+hauser",
    )

    _ROLE_BY_PROTOCOL: ClassVar[dict[str, DeviceRole]] = {
        "modbus_tcp": DeviceRole.PLC,
        "siemens_s7": DeviceRole.PLC,
        "ethernet_ip": DeviceRole.PLC,
        "dnp3": DeviceRole.RTU,
        "bacnet": DeviceRole.BUILDING_AUTOMATION,
        "opc_ua": DeviceRole.HISTORIAN,
        "iec_60870_5_104": DeviceRole.RTU,
        "profinet": DeviceRole.PLC,
        "omron_fins": DeviceRole.PLC,
        "mitsubishi_melsec": DeviceRole.PLC,
        "codesys": DeviceRole.PLC,
    }

    def classify(
        self, devices: list[NetworkDevice]
    ) -> tuple[list[NetworkDevice], list[ICSObservation]]:
        out_devices: list[NetworkDevice] = []
        observations: list[ICSObservation] = []
        for device in devices:
            updates, obs = self._classify_one(device)
            if updates:
                out_devices.append(device.model_copy(update=updates))
            else:
                out_devices.append(device)
            observations.extend(obs)
        return out_devices, observations

    def _classify_one(
        self, device: NetworkDevice
    ) -> tuple[dict[str, object], list[ICSObservation]]:
        updates: dict[str, object] = {}
        observations: list[ICSObservation] = []
        protocols_seen: list[str] = list(device.ics_protocols)
        notes: list[str] = list(device.notes)
        role: DeviceRole = device.role

        # Vendor hint -> role guess only (no protocol assertion).
        vendor = (device.vendor_name or "").lower()
        vendor_hits = any(hint in vendor for hint in self._OT_VENDOR_HINTS)

        # Port signature -> protocol detection.
        for port in device.observed_ports:
            defn = protocol_for_port(port)
            if defn is None:
                continue
            if defn.protocol.value not in protocols_seen:
                protocols_seen.append(defn.protocol.value)
            observations.append(
                ICSObservation(
                    device_id=device.device_id,
                    protocol=defn.protocol,
                    port=port,
                    detection_method="port_signature",
                    confidence=0.7,
                    reasons=[
                        f"Listening on port {port} matches {defn.protocol.value} "
                        f"({defn.description})"
                    ],
                )
            )
            hint = self._ROLE_BY_PROTOCOL.get(defn.protocol.value)
            if hint is not None and role == DeviceRole.UNKNOWN:
                role = hint

        # Boost confidence if vendor and port agree.
        confidence_floor = device.confidence
        if observations and vendor_hits:
            confidence_floor = max(confidence_floor, 0.85)
            notes.append("Vendor OUI and ICS port signature agree.")
        elif observations:
            confidence_floor = max(confidence_floor, 0.7)
        elif vendor_hits and role == DeviceRole.UNKNOWN:
            role = DeviceRole.PLC
            notes.append("Suspected PLC from vendor OUI only; no port evidence.")
            confidence_floor = max(confidence_floor, 0.55)

        tags = list(device.tags)
        if protocols_seen:
            for proto in protocols_seen:
                tag = f"ics:{proto}"
                if tag not in tags:
                    tags.append(tag)

        if (
            protocols_seen != device.ics_protocols
            or role != device.role
            or tags != device.tags
            or notes != device.notes
            or confidence_floor != device.confidence
        ):
            updates = {
                "ics_protocols": protocols_seen,
                "role": role,
                "tags": tags,
                "notes": notes,
                "confidence": confidence_floor,
            }
        return updates, observations

    @staticmethod
    def vendor_summary() -> list[str]:
        return sorted({vendor for entry in ICS_PORT_REGISTRY for vendor in entry.vendors})
