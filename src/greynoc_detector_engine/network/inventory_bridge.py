"""Translate NetworkDevice rows into AssetRecord rows so discovered devices
automatically participate in target-likelihood scoring."""

from __future__ import annotations

from greynoc_detector_engine.models.asset import (
    AssetCriticality,
    AssetExposure,
    AssetRecord,
)
from greynoc_detector_engine.models.network import DeviceRole, NetworkDevice

# Discovered devices are by default INTERNAL/MEDIUM. Operators can override
# in their inventory YAML; this is only the auto-bootstrapped baseline.
_ROLE_CRITICALITY: dict[DeviceRole, AssetCriticality] = {
    DeviceRole.UNKNOWN: AssetCriticality.LOW,
    DeviceRole.WORKSTATION: AssetCriticality.MEDIUM,
    DeviceRole.LAPTOP: AssetCriticality.MEDIUM,
    DeviceRole.PHONE: AssetCriticality.LOW,
    DeviceRole.PRINTER: AssetCriticality.LOW,
    DeviceRole.SERVER: AssetCriticality.HIGH,
    DeviceRole.ROUTER: AssetCriticality.HIGH,
    DeviceRole.SWITCH: AssetCriticality.HIGH,
    DeviceRole.AP: AssetCriticality.MEDIUM,
    DeviceRole.CAMERA: AssetCriticality.MEDIUM,
    DeviceRole.IOT: AssetCriticality.LOW,
    DeviceRole.PLC: AssetCriticality.CROWN_JEWEL,
    DeviceRole.HMI: AssetCriticality.HIGH,
    DeviceRole.SCADA: AssetCriticality.CROWN_JEWEL,
    DeviceRole.HISTORIAN: AssetCriticality.HIGH,
    DeviceRole.RTU: AssetCriticality.CROWN_JEWEL,
    DeviceRole.BUILDING_AUTOMATION: AssetCriticality.HIGH,
}


def asset_from_device(device: NetworkDevice) -> AssetRecord:
    """Convert a NetworkDevice into a baseline AssetRecord for inventory."""
    name = (
        device.hostnames[0]
        if device.hostnames
        else (device.ip_addresses[0] if device.ip_addresses else device.device_id)
    )
    criticality = _ROLE_CRITICALITY.get(device.role, AssetCriticality.MEDIUM)
    tags = list({*device.tags, *(f"role:{device.role.value}",)})
    if device.ics_protocols:
        tags.append("ot")
    return AssetRecord(
        asset_id=device.device_id,
        name=name,
        vendor=device.vendor_name,
        product=(device.role.value if device.role != DeviceRole.UNKNOWN else None),
        exposure=AssetExposure.INTERNAL,
        criticality=criticality,
        tags=sorted(set(tags)),
        last_seen=device.last_seen,
    )


def assets_from_devices(devices: list[NetworkDevice]) -> list[AssetRecord]:
    return [asset_from_device(d) for d in devices]
