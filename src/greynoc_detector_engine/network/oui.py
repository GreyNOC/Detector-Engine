"""Tiny built-in MAC OUI -> vendor lookup.

We ship a small curated registry of the most operationally relevant prefixes
for SOC defenders: ICS vendors, network gear, common workstation/server
manufacturers. For a richer mapping ship the IEEE OUI list at deploy time;
this module is the always-available baseline.
"""

from __future__ import annotations

from typing import Final

from greynoc_detector_engine.models.network import DeviceRole

# Each entry is (prefix_uppercase_no_separator, vendor_name, default_role_hint).
# We match by *prefix* of the normalized MAC (no colons, uppercase).
_OUI_TABLE: Final[list[tuple[str, str, DeviceRole]]] = [
    # --- ICS / OT ---
    ("000FA3", "Allen-Bradley / Rockwell", DeviceRole.PLC),
    ("001D9C", "Rockwell Automation", DeviceRole.PLC),
    ("00C0FF", "Schneider Electric", DeviceRole.PLC),
    ("0080F4", "Schneider Electric", DeviceRole.PLC),
    ("00E04B", "Siemens AG", DeviceRole.PLC),
    ("001B1B", "Siemens AG", DeviceRole.PLC),
    ("00056E", "Mitsubishi Electric", DeviceRole.PLC),
    ("0050C2", "Omron Corporation", DeviceRole.PLC),
    ("000FBB", "Phoenix Contact", DeviceRole.PLC),
    ("AC64DD", "Beckhoff Automation", DeviceRole.PLC),
    ("0011BC", "Endress+Hauser", DeviceRole.PLC),
    ("0001CB", "Yokogawa Electric", DeviceRole.HISTORIAN),
    ("0040AF", "GE Industrial Systems", DeviceRole.PLC),
    ("0080A3", "Lantronix", DeviceRole.RTU),
    ("0050BA", "D-Link / OEM", DeviceRole.UNKNOWN),
    ("000FFE", "Honeywell", DeviceRole.PLC),
    # --- Network gear ---
    ("001A2B", "Cisco Systems", DeviceRole.ROUTER),
    ("E0CB4E", "Cisco Systems", DeviceRole.ROUTER),
    ("F40F1B", "Cisco Systems", DeviceRole.SWITCH),
    ("0001E8", "Cisco Systems", DeviceRole.SWITCH),
    ("00226B", "Cisco-Linksys", DeviceRole.ROUTER),
    ("00193B", "Juniper Networks", DeviceRole.ROUTER),
    ("843835", "Juniper Networks", DeviceRole.ROUTER),
    ("0050DA", "3COM Corporation", DeviceRole.SWITCH),
    ("000C42", "Routerboard / MikroTik", DeviceRole.ROUTER),
    ("E48D8C", "Routerboard / MikroTik", DeviceRole.ROUTER),
    ("00126F", "Ubiquiti Networks", DeviceRole.AP),
    ("248A07", "Ubiquiti Networks", DeviceRole.AP),
    ("FCECDA", "Ubiquiti Networks", DeviceRole.AP),
    ("00904B", "Aruba Networks", DeviceRole.AP),
    ("F827C0", "Aruba Networks", DeviceRole.AP),
    ("000C29", "VMware ESXi", DeviceRole.SERVER),
    ("00505A", "VMware ESXi", DeviceRole.SERVER),
    ("000569", "VMware Inc.", DeviceRole.SERVER),
    # --- Workstations / laptops / phones ---
    ("0050C2", "Apple, Inc.", DeviceRole.LAPTOP),
    ("3C0754", "Apple, Inc.", DeviceRole.LAPTOP),
    ("F0DBE2", "Apple, Inc.", DeviceRole.PHONE),
    ("E4CE8F", "Apple, Inc.", DeviceRole.LAPTOP),
    ("9C2A70", "Apple, Inc.", DeviceRole.PHONE),
    ("00159D", "Dell Inc.", DeviceRole.WORKSTATION),
    ("00188B", "Dell Inc.", DeviceRole.WORKSTATION),
    ("D481D7", "Dell Inc.", DeviceRole.LAPTOP),
    ("70B5E8", "Lenovo Group", DeviceRole.LAPTOP),
    ("AC162D", "Hewlett Packard", DeviceRole.WORKSTATION),
    ("D4BED9", "Hewlett Packard", DeviceRole.WORKSTATION),
    ("38EAA7", "Samsung Electronics", DeviceRole.PHONE),
    ("18E29F", "Samsung Electronics", DeviceRole.PHONE),
    ("BC926B", "Google / Pixel", DeviceRole.PHONE),
    ("F4F5D8", "Google / Nest", DeviceRole.IOT),
    ("18B430", "Nest Labs", DeviceRole.IOT),
    ("28EF01", "Microsoft Corporation", DeviceRole.WORKSTATION),
    ("00155D", "Microsoft Hyper-V VM", DeviceRole.SERVER),
    # --- IoT / cameras / printers ---
    ("BCDDC2", "Hikvision", DeviceRole.CAMERA),
    ("C40363", "Hikvision", DeviceRole.CAMERA),
    ("4C11BF", "Dahua Technology", DeviceRole.CAMERA),
    ("000874", "Axis Communications", DeviceRole.CAMERA),
    ("00408C", "Axis Communications", DeviceRole.CAMERA),
    ("0023A7", "Reolink", DeviceRole.CAMERA),
    ("000874", "HP Printer", DeviceRole.PRINTER),
    ("3C2AF4", "Brother Industries", DeviceRole.PRINTER),
    ("00219B", "Canon Inc.", DeviceRole.PRINTER),
    ("0080A1", "Brocade / Printer OEM", DeviceRole.PRINTER),
]


def normalize_mac(mac: str) -> str:
    """Strip separators and uppercase a MAC string."""
    return "".join(ch for ch in mac if ch.isalnum()).upper()


def lookup_oui(mac: str) -> tuple[str, str, DeviceRole] | None:
    """Return (oui_prefix, vendor_name, role_hint) for a MAC, or None.

    Match is longest-prefix-first so a 6-hex (24-bit) OUI wins over a generic
    catch-all if both happen to overlap.
    """
    if not mac:
        return None
    normalized = normalize_mac(mac)
    if len(normalized) < 6:
        return None
    # Longest prefix wins.
    candidates = sorted(_OUI_TABLE, key=lambda row: len(row[0]), reverse=True)
    for prefix, vendor, role in candidates:
        if normalized.startswith(prefix):
            return prefix, vendor, role
    return None
