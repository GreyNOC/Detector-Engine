"""Known ICS protocols and their canonical TCP/UDP ports."""

from __future__ import annotations

from typing import Final

from pydantic import BaseModel, ConfigDict, Field

from greynoc_detector_engine.models.network import ICSProtocol


class ICSProtocolDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    protocol: ICSProtocol
    ports: list[int] = Field(min_length=1)
    transport: str = "tcp"  # "tcp", "udp", "both"
    vendors: list[str] = Field(default_factory=list)
    description: str
    safety_critical: bool = True


ICS_PORT_REGISTRY: Final[list[ICSProtocolDefinition]] = [
    ICSProtocolDefinition(
        protocol=ICSProtocol.MODBUS_TCP,
        ports=[502],
        transport="tcp",
        vendors=["Schneider Electric", "Rockwell", "Siemens", "many"],
        description="Modbus over TCP — read/write registers on PLCs.",
    ),
    ICSProtocolDefinition(
        protocol=ICSProtocol.SIEMENS_S7,
        ports=[102],
        transport="tcp",
        vendors=["Siemens AG"],
        description="Siemens S7Comm over ISO-on-TCP (RFC 1006).",
    ),
    ICSProtocolDefinition(
        protocol=ICSProtocol.DNP3,
        ports=[20000],
        transport="tcp",
        vendors=["GE", "ABB", "SEL", "utilities"],
        description="DNP3 outstation/master; common in utilities.",
    ),
    ICSProtocolDefinition(
        protocol=ICSProtocol.ETHERNET_IP,
        ports=[44818, 2222],
        transport="both",
        vendors=["Rockwell Allen-Bradley", "ODVA"],
        description="EtherNet/IP explicit (44818) and implicit (2222) messaging.",
    ),
    ICSProtocolDefinition(
        protocol=ICSProtocol.BACNET,
        ports=[47808],
        transport="udp",
        vendors=["building automation OEMs"],
        description="BACnet/IP for HVAC and building automation.",
    ),
    ICSProtocolDefinition(
        protocol=ICSProtocol.OPC_UA,
        ports=[4840],
        transport="tcp",
        vendors=["many"],
        description="OPC UA secure channel default port.",
    ),
    ICSProtocolDefinition(
        protocol=ICSProtocol.IEC_60870_5_104,
        ports=[2404],
        transport="tcp",
        vendors=["utilities", "substation gateways"],
        description="IEC 60870-5-104 telecontrol over TCP.",
    ),
    ICSProtocolDefinition(
        protocol=ICSProtocol.PROFINET,
        ports=[34962, 34963, 34964],
        transport="udp",
        vendors=["Siemens", "Profibus & Profinet International"],
        description="Profinet I/O — Siemens-led industrial ethernet.",
    ),
    ICSProtocolDefinition(
        protocol=ICSProtocol.FINS,
        ports=[9600],
        transport="both",
        vendors=["Omron"],
        description="Omron FINS protocol over TCP/UDP.",
    ),
    ICSProtocolDefinition(
        protocol=ICSProtocol.MELSEC,
        ports=[1025, 5007],
        transport="tcp",
        vendors=["Mitsubishi Electric"],
        description="Mitsubishi MELSEC/SLMP.",
    ),
    ICSProtocolDefinition(
        protocol=ICSProtocol.CODESYS,
        ports=[1200, 2455],
        transport="tcp",
        vendors=["3S-Smart Software / CODESYS"],
        description="CODESYS runtime control channel.",
    ),
]


def protocol_for_port(port: int, transport: str = "tcp") -> ICSProtocolDefinition | None:
    """Return the ICS protocol that owns a port, or None."""
    transport = transport.lower()
    for entry in ICS_PORT_REGISTRY:
        if port not in entry.ports:
            continue
        if entry.transport == "both" or entry.transport == transport:
            return entry
    return None


ICS_PORTS: Final[set[int]] = {port for entry in ICS_PORT_REGISTRY for port in entry.ports}
