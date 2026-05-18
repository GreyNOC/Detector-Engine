"""Spacestation: lightweight, passive-first intrusion sensor.

The spacestation is a thin layer that:

  * Reads the OS TCP/UDP connection table (``netstat``/``Get-NetTCPConnection``)
    and turns it into structured ConnectionRecord rows. No packet capture.
  * Looks for scan patterns (port scan, slow scan, SYN flood, port-knock,
    ICS-port probing, darknet touches) in those records.
  * Optionally runs a darknet TCP listener — any inbound connection is a
    high-confidence malicious signal because the port has no legitimate
    purpose. We close immediately with a RST and never echo anything back.

Everything is intentionally tiny. No raw sockets, no admin requirement,
no extra dependencies. The goal is "even the smallest probe leaves a trace
in our SIEM" — and the engine's normal correlation/predictive layers
already know what to do with structured threat signals.
"""

from greynoc_detector_engine.spacestation.honeypot import (
    DarknetHoneypot,
    HoneypotConfig,
)
from greynoc_detector_engine.spacestation.scan_detector import (
    ScanDetectionConfig,
    ScanDetector,
)
from greynoc_detector_engine.spacestation.sensor import ConnectionTableSensor

__all__ = [
    "ConnectionTableSensor",
    "DarknetHoneypot",
    "HoneypotConfig",
    "ScanDetectionConfig",
    "ScanDetector",
]
