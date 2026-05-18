# Local Network, ICS, and Spacestation Sensor

This module turns the engine from a pure OSINT aggregator into a defender
that also knows what's connected to *your own* network and notices anything
that probes it.

## Trust boundary

- **No packets are sent.** Discovery reads the OS ARP cache (`arp -a` on
  Windows, `ip neigh show` on Linux, `arp -an` POSIX fallback). The sensor
  reads the OS TCP/UDP state table (`netstat -ano` on Windows, `ss -tan`
  on Linux). Nothing is sniffed, scanned, or otherwise emitted.
- **Only the local network.** `in_local_subnet()` refuses to operate on IPs
  outside the host's connected subnets.
- **ICS is detection-only.** We classify devices by MAC OUI + observed port
  fingerprints. We never speak Modbus/S7/DNP3/BACnet/OPC-UA — those
  protocols are typically unauthenticated and an accidental write can be
  an industrial-safety incident.
- **Honeypot is a darknet socket.** We bind an unused TCP port, accept
  connections, optionally capture a bounded preview of the first bytes,
  log the event, and close hard. We **never** write anything back to the
  remote.

## Components

### Discovery (`network/discovery.py`)
- `PassiveDiscovery.discover()` returns `NetworkDevice` rows from the OS
  ARP/neighbor table. MAC vendor + role hint comes from `network/oui.py`.

### ICS module (`ics/`)
- `ICS_PORT_REGISTRY` defines canonical ports for Modbus, S7, DNP3,
  EtherNet/IP, BACnet, OPC UA, IEC 60870-5-104, Profinet, FINS, MELSEC,
  CODESYS.
- `ICSDeviceClassifier` upgrades a device's role to PLC/RTU/HMI/etc. when
  vendor OUI and observed ports agree. It emits `ICSObservation` records.
- `ICSAdvisoryJoiner.join()` maps each classified device to relevant
  CVE/KEV/threat records already in storage so OT-relevant advisories
  surface against the actual at-risk asset.

### Spacestation (`spacestation/`)
- `ConnectionTableSensor.snapshot()` returns `ConnectionRecord` rows from
  the OS connection state.
- `ScanDetector.detect()` walks those records and emits `IntrusionSignal`s:
  `PORT_SCAN`, `SLOW_SCAN`, `SYN_FLOOD`, `PORT_KNOCK`, `ICS_PROBE`,
  `DARKNET_TOUCH`.
- `DarknetHoneypot` is an asyncio TCP listener that emits a `HoneypotEvent`
  for every touch and never speaks any protocol back.

### Wiring (`spacestation/orchestrator.py`)
- `run_discovery_job(storage)` → persists devices, ICS observations, and
  auto-bootstraps the asset inventory.
- `run_sensor_job(storage)` → snapshot connection table, detect scans,
  persist signals, and materialize high-severity signals into synthetic
  `ThreatRecord`s so the predictive engine surfaces live intrusions.
- `local_intrusion_pressure(storage)` → aggregates recent intrusion
  signals into a [0, 1] feature value that feeds `PredictiveContext`.

## CLI

```powershell
greynoc-detector network discover         # passive ARP read; persist devices + ICS tags
greynoc-detector network devices          # list devices
greynoc-detector network ics              # list ICS observations

greynoc-detector sensor run               # one-shot: snapshot + scan detection
greynoc-detector sensor signals           # list recent intrusion signals
greynoc-detector sensor honeypot --port 31337 --label core-net-darknet
```

## API

```
POST /network/discover
GET  /network/devices
GET  /network/ics-observations
POST /sensor/run
GET  /sensor/signals
GET  /sensor/honeypot/events
```

## Predictive feedback loop

Every detected scan signal feeds into `PredictiveFeatures.local_intrusion_pressure`,
which is the third-highest fusion weight in the default model (after EPSS
and KEV). When a scan is firing against an asset whose product matches a
known CVE, the forecast horizon collapses to IMMINENT and the predictive
score spikes — *that is the point of having a local sensor*.

## What this is not

- **Not** a packet sniffer. No libpcap, no raw sockets, no promiscuous mode.
- **Not** an active scanner. The engine never sends probes to learn about
  remote hosts.
- **Not** an ICS protocol speaker. We *recognize* PLC traffic patterns; we
  never originate any.
- **Not** a SIEM. The OS connection table is a thin slice. For full
  visibility, ship NetFlow/Zeek/Suricata/EDR telemetry into your SIEM as
  usual; this module is the always-available baseline.
