"""Read the OS TCP/UDP connection state table into ConnectionRecord rows.

Linux/macOS: ``ss -tan`` (preferred) then ``netstat -tan`` fallback.
Windows:     ``netstat -ano`` then ``Get-NetTCPConnection`` (PowerShell).

We never sniff packets. We never resolve names. The output is a plain
structured snapshot of "who's talking to whom right now".
"""

from __future__ import annotations

import platform
import re
import subprocess
from collections.abc import Iterable

from greynoc_detector_engine.models.network import ConnectionRecord
from greynoc_detector_engine.utils.time import utc_now

_WIN_NETSTAT_LINE = re.compile(
    r"^\s*(TCP|UDP)\s+(\S+):(\d+)\s+(\S+):(\d+|\*)\s+(\S+)?\s*(\d+)?\s*$"
)
_POSIX_SS_LINE = re.compile(r"^(\S+)\s+(\d+)\s+(\d+)\s+(\S+):(\d+|\*)\s+(\S+):(\d+|\*)\s*")
_POSIX_NETSTAT_LINE = re.compile(
    r"^(tcp|udp)[46]?\s+\d+\s+\d+\s+(\S+):(\d+|\*)\s+(\S+):(\d+|\*)\s+(\S+)?"
)


class SensorError(RuntimeError):
    pass


class ConnectionTableSensor:
    """Snapshot the OS connection table without sending packets."""

    def __init__(self, *, command_runner=None) -> None:  # type: ignore[no-untyped-def]
        self._run = command_runner or self._default_runner

    # -- public --------------------------------------------------------------

    def snapshot(self) -> list[ConnectionRecord]:
        system = platform.system().lower()
        if system == "windows":
            return self.parse_windows_netstat(self._run(["netstat", "-ano"]))
        try:
            return self.parse_ss(self._run(["ss", "-tan"]))
        except SensorError:
            return self.parse_posix_netstat(self._run(["netstat", "-tan"]))

    # -- parsers (pure) ------------------------------------------------------

    @staticmethod
    def parse_windows_netstat(text: str) -> list[ConnectionRecord]:
        out: list[ConnectionRecord] = []
        for line in text.splitlines():
            m = _WIN_NETSTAT_LINE.match(line)
            if not m:
                continue
            proto = m.group(1).lower()
            local_addr = _strip_v6_brackets(m.group(2))
            local_port = int(m.group(3))
            remote_addr = _strip_v6_brackets(m.group(4))
            remote_port = _parse_port(m.group(5))
            state = (m.group(6) or "").upper()
            pid = int(m.group(7)) if m.group(7) else None
            out.append(
                ConnectionRecord(
                    protocol=proto,
                    local_address=local_addr,
                    local_port=local_port,
                    remote_address=remote_addr,
                    remote_port=remote_port,
                    state=state or _default_state(proto),
                    pid=pid,
                    observed_at=utc_now(),
                )
            )
        return out

    @staticmethod
    def parse_ss(text: str) -> list[ConnectionRecord]:
        out: list[ConnectionRecord] = []
        for line in text.splitlines():
            # Skip headers
            if line.startswith("State") or line.startswith("Netid"):
                continue
            m = _POSIX_SS_LINE.match(line)
            if not m:
                continue
            state = m.group(1).upper()
            local_addr = _strip_v6_brackets(m.group(4))
            local_port = _parse_port(m.group(5))
            remote_addr = _strip_v6_brackets(m.group(6))
            remote_port = _parse_port(m.group(7))
            out.append(
                ConnectionRecord(
                    protocol="tcp",
                    local_address=local_addr,
                    local_port=local_port,
                    remote_address=remote_addr,
                    remote_port=remote_port,
                    state=state,
                    pid=None,
                    observed_at=utc_now(),
                )
            )
        return out

    @staticmethod
    def parse_posix_netstat(text: str) -> list[ConnectionRecord]:
        out: list[ConnectionRecord] = []
        for line in text.splitlines():
            m = _POSIX_NETSTAT_LINE.match(line)
            if not m:
                continue
            proto = m.group(1).lower()
            out.append(
                ConnectionRecord(
                    protocol=proto,
                    local_address=_strip_v6_brackets(m.group(2)),
                    local_port=_parse_port(m.group(3)),
                    remote_address=_strip_v6_brackets(m.group(4)),
                    remote_port=_parse_port(m.group(5)),
                    state=(m.group(6) or _default_state(proto)).upper(),
                    pid=None,
                    observed_at=utc_now(),
                )
            )
        return out

    # -- helpers -------------------------------------------------------------

    @staticmethod
    def _default_runner(cmd: list[str]) -> str:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
        except FileNotFoundError as exc:
            raise SensorError(f"command not found: {cmd[0]}") from exc
        except subprocess.TimeoutExpired as exc:
            raise SensorError(f"command timed out: {' '.join(cmd)}") from exc
        if result.returncode != 0:
            raise SensorError(f"command failed: {' '.join(cmd)} -> {result.stderr.strip()}")
        return result.stdout


def listening_ports(records: Iterable[ConnectionRecord]) -> set[int]:
    """Return the set of locally-listening ports."""
    return {r.local_port for r in records if r.state in {"LISTEN", "LISTENING"}}


def _strip_v6_brackets(addr: str) -> str:
    return addr.strip("[]")


def _parse_port(token: str) -> int:
    if token == "*":
        return 0
    try:
        return int(token)
    except ValueError:
        return 0


def _default_state(proto: str) -> str:
    return "LISTEN" if proto == "tcp" else "OPEN"
