"""Join classified ICS devices to the engine's existing CVE/KEV/threat data.

Approach: build a fast index of CVE descriptions, KEV vendor/product, and
threat-record titles for ICS-vendor keywords; for each device, return the
matching threats so the predictive engine can localize OT-relevant alerts
to the actual at-risk PLC/RTU/HMI.
"""

from __future__ import annotations

from collections import defaultdict

from greynoc_detector_engine.models.cve import CVERecord
from greynoc_detector_engine.models.kev import KEVRecord
from greynoc_detector_engine.models.network import NetworkDevice
from greynoc_detector_engine.models.threat import ThreatRecord


class ICSAdvisoryJoiner:
    """Map each ICS device to threats/CVE/KEV records that reference its vendor."""

    def join(
        self,
        devices: list[NetworkDevice],
        *,
        cves: list[CVERecord] | None = None,
        kev_entries: list[KEVRecord] | None = None,
        threats: list[ThreatRecord] | None = None,
    ) -> dict[str, list[str]]:
        cves = cves or []
        kev_entries = kev_entries or []
        threats = threats or []

        device_keywords: dict[str, set[str]] = defaultdict(set)
        for device in devices:
            for keyword in self._keywords_for_device(device):
                device_keywords[device.device_id].add(keyword)

        results: dict[str, list[str]] = defaultdict(list)
        for device in devices:
            keywords = device_keywords[device.device_id]
            if not keywords:
                continue
            for cve in cves:
                if self._matches_keywords(
                    [cve.description, " ".join(cve.affected_products)], keywords
                ):
                    results[device.device_id].append(cve.cve_id)
            for kev in kev_entries:
                blob = " ".join([kev.vendor_project, kev.product, kev.vulnerability_name])
                if self._matches_keywords([blob], keywords):
                    results[device.device_id].append(kev.cve_id)
            for threat in threats:
                blob = " ".join([threat.title, threat.summary, *threat.affected_products])
                if self._matches_keywords([blob], keywords):
                    results[device.device_id].append(threat.threat_id)
        # Deduplicate while preserving order.
        return {dev: list(dict.fromkeys(refs)) for dev, refs in results.items()}

    @staticmethod
    def _keywords_for_device(device: NetworkDevice) -> set[str]:
        kws: set[str] = set()
        if device.vendor_name:
            # First token, lowercased, e.g. "Allen-Bradley" -> "allen-bradley"
            kws.add(device.vendor_name.split()[0].lower())
            kws.add(device.vendor_name.lower())
        for protocol in device.ics_protocols:
            kws.add(protocol.lower())
        for tag in device.tags:
            if tag.startswith("ics:"):
                kws.add(tag.split(":", 1)[1].lower())
        return {k for k in kws if len(k) >= 4}

    @staticmethod
    def _matches_keywords(blobs: list[str], keywords: set[str]) -> bool:
        blob = " ".join(blob.lower() for blob in blobs if blob)
        return any(keyword in blob for keyword in keywords)
