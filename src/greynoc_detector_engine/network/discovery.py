"""Passive local-network discovery.

We never send packets. We read the OS ARP cache (Windows: ``arp -a``,
POSIX: ``ip neigh show`` with a fallback to ``arp -an``) and merge results
with anything the caller provides (DHCP lease files, hostname tables).

Active ICMP/ARP probing of the local subnet is an explicit opt-in flag and
is bounded by the host's own connected interfaces — we refuse to probe
anything outside the OS-reported local subnets.
"""

from __future__ import annotations

import ipaddress
import platform
import re
import subprocess
from collections.abc import Iterable
from dataclasses import dataclass

from greynoc_detector_engine.models.network import (
    DiscoveryMethod,
    NetworkDevice,
    NetworkInterface,
)
from greynoc_detector_engine.network.oui import lookup_oui, normalize_mac
from greynoc_detector_engine.utils.hashing import stable_hash
from greynoc_detector_engine.utils.time import utc_now

# Windows `arp -a` line:  "  192.168.1.10        aa-bb-cc-dd-ee-ff     dynamic"
# Linux  `ip neigh show`:  "192.168.1.10 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
# POSIX  `arp -an`:        "? (192.168.1.10) at aa:bb:cc:dd:ee:ff on eth0"
_WINDOWS_ARP_LINE = re.compile(
    r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){5})\s+(\S+)"
)
_LINUX_NEIGH_LINE = re.compile(r"^(\S+)\s+dev\s+(\S+)(?:\s+lladdr\s+([0-9A-Fa-f:]{17}))?\s+(\w+)")
_POSIX_ARP_LINE = re.compile(r"\((\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+([0-9A-Fa-f:]{17})")


@dataclass
class ArpEntry:
    ip: str
    mac: str
    interface: str | None = None
    state: str = "stale"


class DiscoveryError(RuntimeError):
    """Raised when discovery cannot run (no tools available, permission, etc.)."""


class PassiveDiscovery:
    """Read the host OS ARP / neighbor table.

    No packets are emitted; we only parse already-cached neighbor data.
    """

    def __init__(self, *, command_runner=None) -> None:  # type: ignore[no-untyped-def]
        # command_runner is overridable for tests so we don't shell out.
        self._run = command_runner or self._default_runner

    # -- public --------------------------------------------------------------

    def discover(self) -> list[NetworkDevice]:
        entries = self.read_arp_cache()
        return [self._entry_to_device(entry) for entry in entries]

    def read_arp_cache(self) -> list[ArpEntry]:
        system = platform.system().lower()
        if system == "windows":
            return self.parse_windows_arp(self._run(["arp", "-a"]))
        # Try `ip neigh` first (modern Linux), then fall back to `arp -an`.
        try:
            return self.parse_linux_neighbors(self._run(["ip", "neigh", "show"]))
        except DiscoveryError:
            return self.parse_posix_arp(self._run(["arp", "-an"]))

    # -- parsers (pure, testable) -------------------------------------------

    @staticmethod
    def parse_windows_arp(text: str) -> list[ArpEntry]:
        entries: list[ArpEntry] = []
        for line in text.splitlines():
            m = _WINDOWS_ARP_LINE.match(line)
            if not m:
                continue
            entries.append(ArpEntry(ip=m.group(1), mac=m.group(2), state=m.group(3).lower()))
        return entries

    @staticmethod
    def parse_linux_neighbors(text: str) -> list[ArpEntry]:
        entries: list[ArpEntry] = []
        for line in text.splitlines():
            m = _LINUX_NEIGH_LINE.match(line)
            if not m or not m.group(3):
                continue
            entries.append(
                ArpEntry(
                    ip=m.group(1),
                    mac=m.group(3),
                    interface=m.group(2),
                    state=m.group(4).lower(),
                )
            )
        return entries

    @staticmethod
    def parse_posix_arp(text: str) -> list[ArpEntry]:
        entries: list[ArpEntry] = []
        for line in text.splitlines():
            m = _POSIX_ARP_LINE.search(line)
            if not m:
                continue
            entries.append(ArpEntry(ip=m.group(1), mac=m.group(2)))
        return entries

    # -- helpers -------------------------------------------------------------

    @staticmethod
    def _entry_to_device(entry: ArpEntry) -> NetworkDevice:
        mac = normalize_mac(entry.mac) if entry.mac else None
        oui = lookup_oui(mac) if mac else None
        vendor_name = oui[1] if oui else None
        role = oui[2] if oui else None
        device_id = f"net-{stable_hash(mac or entry.ip)}"
        now = utc_now()
        return NetworkDevice(
            device_id=device_id,
            ip_addresses=[entry.ip] if entry.ip else [],
            mac_address=_format_mac(mac) if mac else None,
            vendor_oui=oui[0] if oui else None,
            vendor_name=vendor_name,
            role=role or NetworkDevice.model_fields["role"].default,
            confidence=0.6 if mac else 0.3,
            discovered_via=[DiscoveryMethod.ARP_CACHE],
            first_seen=now,
            last_seen=now,
            notes=([f"Interface {entry.interface}"] if entry.interface else []),
        )

    @staticmethod
    def _default_runner(cmd: list[str]) -> str:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
        except FileNotFoundError as exc:
            raise DiscoveryError(f"command not found: {cmd[0]}") from exc
        except subprocess.TimeoutExpired as exc:
            raise DiscoveryError(f"command timed out: {' '.join(cmd)}") from exc
        if result.returncode != 0:
            raise DiscoveryError(f"command failed: {' '.join(cmd)} -> {result.stderr.strip()}")
        return result.stdout


def _format_mac(normalized: str) -> str:
    return ":".join(normalized[i : i + 2] for i in range(0, 12, 2))


def merge_devices(devices: Iterable[NetworkDevice]) -> list[NetworkDevice]:
    """Combine duplicate observations (same MAC or same IP)."""
    by_key: dict[str, NetworkDevice] = {}
    for device in devices:
        key = (
            (device.mac_address or "")
            + "|"
            + (device.ip_addresses[0] if device.ip_addresses else "")
        )
        existing = by_key.get(key)
        if existing is None:
            by_key[key] = device
            continue
        merged_ips = sorted(set(existing.ip_addresses) | set(device.ip_addresses))
        merged_methods = sorted(
            set(existing.discovered_via) | set(device.discovered_via),
            key=lambda m: m.value,
        )
        merged_ports = sorted(set(existing.observed_ports) | set(device.observed_ports))
        merged_hosts = sorted(set(existing.hostnames) | set(device.hostnames))
        by_key[key] = existing.model_copy(
            update={
                "ip_addresses": merged_ips,
                "discovered_via": merged_methods,
                "observed_ports": merged_ports,
                "hostnames": merged_hosts,
                "last_seen": max(existing.last_seen, device.last_seen),
            }
        )
    return list(by_key.values())


def in_local_subnet(ip: str, interfaces: Iterable[NetworkInterface]) -> bool:
    """Refuse to operate on IPs outside any locally-attached subnet."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for iface in interfaces:
        if not iface.network_cidr:
            continue
        try:
            net = ipaddress.ip_network(iface.network_cidr, strict=False)
        except ValueError:
            continue
        if addr in net:
            return True
    return False
