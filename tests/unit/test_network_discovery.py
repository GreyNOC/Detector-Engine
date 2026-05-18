from __future__ import annotations

from greynoc_detector_engine.models.network import DeviceRole, DiscoveryMethod, NetworkInterface
from greynoc_detector_engine.network.discovery import (
    PassiveDiscovery,
    in_local_subnet,
    merge_devices,
)
from greynoc_detector_engine.network.oui import lookup_oui, normalize_mac

WINDOWS_ARP = """
Interface: 192.168.1.5 --- 0xb
  Internet Address      Physical Address      Type
  192.168.1.1           aa-bb-cc-11-22-33     dynamic
  192.168.1.10          E0-CB-4E-00-01-02     dynamic
  192.168.1.20          00-1B-1B-00-00-01     dynamic
"""

LINUX_NEIGH = """\
192.168.1.1 dev eth0 lladdr aa:bb:cc:11:22:33 REACHABLE
192.168.1.10 dev eth0 lladdr e0:cb:4e:00:01:02 STALE
192.168.1.99 dev eth0  FAILED
"""

POSIX_ARP = """\
? (192.168.1.1) at aa:bb:cc:11:22:33 on en0 ifscope [ethernet]
? (192.168.1.10) at e0:cb:4e:00:01:02 on en0 ifscope [ethernet]
"""


def test_normalize_mac_strips_separators() -> None:
    assert normalize_mac("aa:bb:cc:11:22:33") == "AABBCC112233"
    assert normalize_mac("AA-BB-CC-11-22-33") == "AABBCC112233"


def test_lookup_oui_finds_cisco_prefix() -> None:
    hit = lookup_oui("E0:CB:4E:00:01:02")
    assert hit is not None
    prefix, vendor, role = hit
    assert prefix == "E0CB4E"
    assert "Cisco" in vendor
    assert role == DeviceRole.ROUTER


def test_lookup_oui_finds_siemens_plc() -> None:
    hit = lookup_oui("00:1B:1B:DE:AD:BE")
    assert hit is not None
    _, vendor, role = hit
    assert "Siemens" in vendor
    assert role == DeviceRole.PLC


def test_parse_windows_arp_extracts_entries() -> None:
    entries = PassiveDiscovery.parse_windows_arp(WINDOWS_ARP)
    assert len(entries) == 3
    assert entries[0].ip == "192.168.1.1"
    assert entries[1].mac.lower() == "e0-cb-4e-00-01-02"


def test_parse_linux_neighbors_skips_failed_entries() -> None:
    entries = PassiveDiscovery.parse_linux_neighbors(LINUX_NEIGH)
    assert len(entries) == 2
    assert all(e.mac for e in entries)


def test_parse_posix_arp() -> None:
    entries = PassiveDiscovery.parse_posix_arp(POSIX_ARP)
    assert len(entries) == 2


def test_passive_discovery_with_injected_runner() -> None:
    runner = lambda cmd: WINDOWS_ARP  # noqa: E731
    pd = PassiveDiscovery(command_runner=runner)
    devices = pd.parse_windows_arp(WINDOWS_ARP)
    network_devices = [pd._entry_to_device(e) for e in devices]
    assert all(DiscoveryMethod.ARP_CACHE in d.discovered_via for d in network_devices)
    cisco = next(d for d in network_devices if d.ip_addresses == ["192.168.1.10"])
    assert cisco.role == DeviceRole.ROUTER
    siemens = next(d for d in network_devices if d.ip_addresses == ["192.168.1.20"])
    assert siemens.role == DeviceRole.PLC


def test_merge_devices_combines_duplicate_observations() -> None:
    pd = PassiveDiscovery()
    a = pd._entry_to_device(
        type(
            "E",
            (),
            {"ip": "192.168.1.10", "mac": "e0:cb:4e:00:01:02", "interface": None, "state": "ok"},
        )()
    )
    b = pd._entry_to_device(
        type(
            "E",
            (),
            {"ip": "192.168.1.10", "mac": "e0:cb:4e:00:01:02", "interface": "eth0", "state": "ok"},
        )()
    )
    merged = merge_devices([a, b])
    assert len(merged) == 1


def test_in_local_subnet_refuses_external_ip() -> None:
    interfaces = [
        NetworkInterface(name="eth0", ipv4="192.168.1.5", network_cidr="192.168.1.0/24"),
    ]
    assert in_local_subnet("192.168.1.50", interfaces)
    assert not in_local_subnet("8.8.8.8", interfaces)
