from __future__ import annotations

import asyncio
import contextlib
import socket
from datetime import timedelta

from greynoc_detector_engine.models.network import (
    ConnectionRecord,
    IntrusionKind,
    IntrusionSeverity,
)
from greynoc_detector_engine.spacestation.honeypot import (
    DarknetHoneypot,
    HoneypotConfig,
)
from greynoc_detector_engine.spacestation.scan_detector import (
    ScanDetectionConfig,
    ScanDetector,
)
from greynoc_detector_engine.spacestation.sensor import (
    ConnectionTableSensor,
    listening_ports,
)
from greynoc_detector_engine.utils.time import utc_now

WINDOWS_NETSTAT = """
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    192.168.1.5:50111      203.0.113.7:80         ESTABLISHED     1234
  TCP    192.168.1.5:22         203.0.113.99:55012     SYN_RECV        2222
  TCP    192.168.1.5:443        203.0.113.99:55013     SYN_RECV        2222
  UDP    0.0.0.0:5353           *:*                                    9876
"""


def _conn(
    remote: str,
    port: int,
    state: str = "ESTABLISHED",
    local: str = "192.168.1.5",
    seconds_ago: float = 0.0,
    remote_port: int = 55000,
) -> ConnectionRecord:
    return ConnectionRecord(
        protocol="tcp",
        local_address=local,
        local_port=port,
        remote_address=remote,
        remote_port=remote_port,
        state=state,
        observed_at=utc_now() - timedelta(seconds=seconds_ago),
    )


def test_parse_windows_netstat_yields_records() -> None:
    records = ConnectionTableSensor.parse_windows_netstat(WINDOWS_NETSTAT)
    states = {r.state for r in records}
    assert "LISTENING" in states
    assert "ESTABLISHED" in states
    assert "SYN_RECV" in states


def test_listening_ports_extraction() -> None:
    records = ConnectionTableSensor.parse_windows_netstat(WINDOWS_NETSTAT)
    assert 445 in listening_ports(records)


def test_port_scan_detector_fires_on_distinct_ports() -> None:
    detector = ScanDetector(ScanDetectionConfig(fast_port_threshold=4, fast_window_seconds=60))
    records = [_conn("203.0.113.50", port=port) for port in (22, 80, 443, 3389, 8080)]
    signals = detector.detect(records)
    kinds = {s.kind for s in signals}
    assert IntrusionKind.PORT_SCAN in kinds
    scan = next(s for s in signals if s.kind == IntrusionKind.PORT_SCAN)
    assert scan.severity == IntrusionSeverity.HIGH
    assert len(scan.target_ports) >= 4


def test_syn_flood_detector() -> None:
    detector = ScanDetector(ScanDetectionConfig(syn_flood_threshold=5))
    records = [
        _conn("203.0.113.99", port=80, state="SYN_RECV", remote_port=p) for p in range(40000, 40010)
    ]
    signals = detector.detect(records)
    assert any(s.kind == IntrusionKind.SYN_FLOOD for s in signals)


def test_ics_inbound_signal_fires_on_known_port() -> None:
    detector = ScanDetector(ScanDetectionConfig(treat_ics_inbound_as_signal=True))
    records = [_conn("203.0.113.7", port=502)]
    signals = detector.detect(records)
    ics = [s for s in signals if s.kind == IntrusionKind.ICS_PROBE]
    assert ics, "ICS port (502, Modbus) should trigger ICS_PROBE"


def test_darknet_touch_signal() -> None:
    detector = ScanDetector(ScanDetectionConfig(darknet_ports=[31337]))
    records = [_conn("203.0.113.1", port=31337)]
    signals = detector.detect(records)
    assert any(s.kind == IntrusionKind.DARKNET_TOUCH for s in signals)
    assert all(s.severity == IntrusionSeverity.CRITICAL for s in signals)


def test_port_knock_detector() -> None:
    detector = ScanDetector(ScanDetectionConfig(knock_min=3, knock_window_seconds=30))
    records = [
        _conn("203.0.113.8", port=1001, seconds_ago=20),
        _conn("203.0.113.8", port=2002, seconds_ago=15),
        _conn("203.0.113.8", port=3003, seconds_ago=5),
    ]
    signals = detector.detect(records)
    assert any(s.kind == IntrusionKind.PORT_KNOCK for s in signals)


def test_loopback_and_multicast_are_excluded_by_default() -> None:
    detector = ScanDetector(
        ScanDetectionConfig(fast_port_threshold=3, treat_ics_inbound_as_signal=False)
    )
    records = [
        _conn("127.0.0.1", port=80),
        _conn("127.0.0.1", port=443),
        _conn("127.0.0.1", port=22),
        _conn("224.0.0.22", port=8080),
        _conn("169.254.1.1", port=1234),
    ]
    signals = detector.detect(records)
    assert signals == []


def test_explicit_address_exclusion() -> None:
    detector = ScanDetector(
        ScanDetectionConfig(
            fast_port_threshold=3,
            exclude_addresses=["10.0.0.5"],
            treat_ics_inbound_as_signal=False,
        )
    )
    records = [_conn("10.0.0.5", port=p) for p in (1, 2, 3, 4)]
    assert detector.detect(records) == []


def test_darknet_honeypot_records_connection() -> None:
    async def scenario() -> None:
        # bind ephemeral port
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        config = HoneypotConfig(label="test", bind_host="127.0.0.1", port=port)
        pot = DarknetHoneypot(config)
        await pot.start()
        # Issue a connection attempt
        _reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"GET / HTTP/1.0\r\n\r\n")
        await writer.drain()
        # Server captures up to N bytes; give it a moment
        await asyncio.sleep(0.2)
        writer.close()
        with contextlib.suppress(OSError):
            await writer.wait_closed()
        await pot.stop()
        assert len(pot.events) == 1
        event = pot.events[0]
        assert event.listener_port == port
        assert event.remote_address in {"127.0.0.1", "::1"}
        assert event.payload_preview is not None
        assert "GET" in event.payload_preview

    asyncio.run(scenario())
