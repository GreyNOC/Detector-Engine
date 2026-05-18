from __future__ import annotations

from typing import Protocol

from greynoc_detector_engine.models.detection import GeneratedDetection
from greynoc_detector_engine.models.threat import ThreatRecord


class DetectionGenerator(Protocol):
    def generate(self, threat: ThreatRecord) -> GeneratedDetection:
        """Return a draft defensive detection for a threat record."""
        ...
