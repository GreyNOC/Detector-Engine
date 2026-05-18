"""ICS (Industrial Control Systems) device classification and advisory joining.

This module is *detection-only*. We never speak Modbus/S7/DNP3/etc on the
wire — those protocols are typically unauthenticated and an accidental
write can cause an industrial-safety incident. We classify devices passively
based on:

  * MAC OUI prefix (Rockwell, Siemens, Schneider, Honeywell, ...)
  * Observed listening ports (Modbus 502, S7 102, DNP3 20000, etc.)
  * Provided hints from the asset inventory

Classified devices feed the predictive engine through the asset inventory
and pull joined CVE/KEV/vendor advisories so OT-aware threats surface
even when the ICS device never appears in our IT-side telemetry.
"""

from greynoc_detector_engine.ics.advisory_join import ICSAdvisoryJoiner
from greynoc_detector_engine.ics.classifier import ICSDeviceClassifier
from greynoc_detector_engine.ics.protocols import (
    ICS_PORT_REGISTRY,
    ICSProtocolDefinition,
)

__all__ = [
    "ICS_PORT_REGISTRY",
    "ICSAdvisoryJoiner",
    "ICSDeviceClassifier",
    "ICSProtocolDefinition",
]
