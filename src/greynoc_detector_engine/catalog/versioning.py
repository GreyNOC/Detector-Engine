from __future__ import annotations

from greynoc_detector_engine.models.threat import ThreatRecord


def bump_version(threat: ThreatRecord, reason: str) -> ThreatRecord:
    updated = threat.model_copy(deep=True)
    updated.version += 1
    updated.changelog.append(reason)
    return updated
