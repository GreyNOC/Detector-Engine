from __future__ import annotations

from greynoc_detector_engine.ics.advisory_join import ICSAdvisoryJoiner
from greynoc_detector_engine.ics.classifier import ICSDeviceClassifier
from greynoc_detector_engine.ics.protocols import (
    ICS_PORTS,
    ICSProtocol,
    protocol_for_port,
)
from greynoc_detector_engine.models.cve import CVERecord
from greynoc_detector_engine.models.kev import KEVRecord
from greynoc_detector_engine.models.network import DeviceRole, NetworkDevice


def _device(**kwargs: object) -> NetworkDevice:
    defaults: dict[str, object] = {
        "device_id": "test-1",
        "ip_addresses": ["10.0.0.10"],
        "mac_address": "00:1B:1B:00:00:01",
        "vendor_name": "Siemens AG",
        "vendor_oui": "001B1B",
        "role": DeviceRole.UNKNOWN,
        "observed_ports": [102, 502],
        "confidence": 0.6,
    }
    defaults.update(kwargs)
    return NetworkDevice(**defaults)  # type: ignore[arg-type]


def test_ics_ports_contains_modbus_and_s7() -> None:
    assert 502 in ICS_PORTS
    assert 102 in ICS_PORTS


def test_protocol_for_port_returns_canonical_protocol() -> None:
    p = protocol_for_port(502)
    assert p is not None and p.protocol == ICSProtocol.MODBUS_TCP
    assert protocol_for_port(47808, transport="udp").protocol == ICSProtocol.BACNET  # type: ignore[union-attr]
    assert protocol_for_port(9999) is None


def test_classifier_emits_observations_for_known_ports() -> None:
    devices, observations = ICSDeviceClassifier().classify([_device()])
    assert len(observations) == 2
    assert {o.protocol for o in observations} == {
        ICSProtocol.MODBUS_TCP,
        ICSProtocol.SIEMENS_S7,
    }
    plc = devices[0]
    assert plc.role == DeviceRole.PLC
    assert "ics:modbus_tcp" in plc.tags
    assert plc.confidence >= 0.85  # vendor + ports agree


def test_classifier_role_unknown_when_no_signals() -> None:
    devices, observations = ICSDeviceClassifier().classify(
        [
            _device(
                vendor_name="Random Vendor",
                vendor_oui="ABCDEF",
                observed_ports=[443, 22],
            )
        ]
    )
    assert devices[0].role == DeviceRole.UNKNOWN
    assert observations == []


def test_advisory_joiner_maps_siemens_device_to_relevant_cve() -> None:
    cves = [
        CVERecord(
            cve_id="CVE-2026-12345",
            description="Siemens S7-1200 PLC affected by command injection.",
            affected_products=["siemens:s7-1200"],
        ),
        CVERecord(
            cve_id="CVE-2024-99999",
            description="Unrelated CMS vulnerability.",
        ),
    ]
    kev = [
        KEVRecord(
            cve_id="CVE-2026-12345",
            vendor_project="Siemens",
            product="S7-1200",
            vulnerability_name="S7-1200 command injection",
            short_description="Siemens S7 issue",
            required_action="Patch",
        )
    ]
    joined = ICSAdvisoryJoiner().join([_device()], cves=cves, kev_entries=kev)
    assert "test-1" in joined
    assert "CVE-2026-12345" in joined["test-1"]
    assert "CVE-2024-99999" not in joined["test-1"]
