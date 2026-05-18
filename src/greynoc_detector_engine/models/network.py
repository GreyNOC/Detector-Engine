"""Pydantic schemas for local-network discovery, ICS classification, and
spacestation (intrusion-sensor) observations."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from greynoc_detector_engine.utils.time import utc_now


class DeviceRole(StrEnum):
    UNKNOWN = "unknown"
    WORKSTATION = "workstation"
    SERVER = "server"
    LAPTOP = "laptop"
    PHONE = "phone"
    PRINTER = "printer"
    ROUTER = "router"
    SWITCH = "switch"
    AP = "access_point"
    CAMERA = "camera"
    IOT = "iot"
    PLC = "plc"
    HMI = "hmi"
    SCADA = "scada"
    HISTORIAN = "historian"
    RTU = "rtu"
    BUILDING_AUTOMATION = "building_automation"


class DiscoveryMethod(StrEnum):
    ARP_CACHE = "arp_cache"
    NEIGHBOR_TABLE = "neighbor_table"
    DHCP_LEASES = "dhcp_leases"
    MDNS = "mdns"
    NETBIOS = "netbios"
    CONNECTION_TABLE = "connection_table"
    USER_PROVIDED = "user_provided"


class NetworkInterface(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    ipv4: str | None = None
    ipv6: str | None = None
    mac: str | None = None
    network_cidr: str | None = None


class NetworkDevice(BaseModel):
    """A device observed on our local network."""

    model_config = ConfigDict(extra="forbid")

    device_id: str
    ip_addresses: list[str] = Field(default_factory=list)
    mac_address: str | None = None
    hostnames: list[str] = Field(default_factory=list)
    vendor_oui: str | None = None
    vendor_name: str | None = None
    role: DeviceRole = DeviceRole.UNKNOWN
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    discovered_via: list[DiscoveryMethod] = Field(default_factory=list)
    observed_ports: list[int] = Field(default_factory=list)
    ics_protocols: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    first_seen: datetime = Field(default_factory=utc_now)
    last_seen: datetime = Field(default_factory=utc_now)
    notes: list[str] = Field(default_factory=list)


class ConnectionRecord(BaseModel):
    """A single TCP/UDP connection observed in the OS state table."""

    model_config = ConfigDict(extra="forbid")

    protocol: str  # "tcp" or "udp"
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    state: str  # ESTABLISHED, LISTEN, SYN_SENT, TIME_WAIT, ...
    pid: int | None = None
    observed_at: datetime = Field(default_factory=utc_now)


class IntrusionKind(StrEnum):
    PORT_SCAN = "port_scan"
    SLOW_SCAN = "slow_scan"
    SYN_FLOOD = "syn_flood"
    PORT_KNOCK = "port_knock"
    DARKNET_TOUCH = "darknet_touch"
    ICS_PROBE = "ics_probe"
    LATERAL_PROBE = "lateral_probe"
    UNUSUAL_OUTBOUND = "unusual_outbound"


class IntrusionSeverity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IntrusionSignal(BaseModel):
    """A single suspicious observation: scan attempt, darknet hit, etc."""

    model_config = ConfigDict(extra="forbid")

    signal_id: str
    kind: IntrusionKind
    severity: IntrusionSeverity
    source_address: str
    source_port: int | None = None
    target_addresses: list[str] = Field(default_factory=list)
    target_ports: list[int] = Field(default_factory=list)
    observation_count: int = Field(default=1, ge=1)
    window_seconds: float = Field(default=0.0, ge=0.0)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    first_seen: datetime = Field(default_factory=utc_now)
    last_seen: datetime = Field(default_factory=utc_now)
    reasons: list[str] = Field(default_factory=list)
    related_device_ids: list[str] = Field(default_factory=list)


class ICSProtocol(StrEnum):
    MODBUS_TCP = "modbus_tcp"
    SIEMENS_S7 = "siemens_s7"
    DNP3 = "dnp3"
    ETHERNET_IP = "ethernet_ip"
    BACNET = "bacnet"
    OPC_UA = "opc_ua"
    IEC_60870_5_104 = "iec_60870_5_104"
    GOOSE = "goose_iec_61850"
    PROFINET = "profinet"
    FINS = "omron_fins"
    MELSEC = "mitsubishi_melsec"
    CODESYS = "codesys"


class ICSObservation(BaseModel):
    """Evidence that a device speaks an ICS protocol."""

    model_config = ConfigDict(extra="forbid")

    device_id: str
    protocol: ICSProtocol
    port: int
    detection_method: str
    confidence: float = Field(ge=0.0, le=1.0)
    reasons: list[str] = Field(default_factory=list)
    observed_at: datetime = Field(default_factory=utc_now)


class HoneypotEvent(BaseModel):
    """A single connection touch on the darknet/honeypot listener."""

    model_config = ConfigDict(extra="forbid")

    event_id: str
    listener_port: int
    listener_label: str
    remote_address: str
    remote_port: int
    payload_preview: str | None = None  # bounded; never echoed to attacker
    bytes_received: int = Field(default=0, ge=0)
    observed_at: datetime = Field(default_factory=utc_now)
