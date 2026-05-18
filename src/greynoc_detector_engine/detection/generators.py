from __future__ import annotations

from greynoc_detector_engine.detection.base import DetectionGenerator
from greynoc_detector_engine.detection.defender import DefenderGenerator
from greynoc_detector_engine.detection.elastic import ElasticGenerator
from greynoc_detector_engine.detection.sigma import SigmaGenerator
from greynoc_detector_engine.detection.splunk import SplunkGenerator
from greynoc_detector_engine.detection.suricata_metadata import SuricataGenerator
from greynoc_detector_engine.detection.yara_metadata import YaraGenerator
from greynoc_detector_engine.models.detection import GeneratedDetection
from greynoc_detector_engine.models.threat import ThreatRecord


class DetectionGeneratorSuite:
    def __init__(self) -> None:
        self.generators: list[DetectionGenerator] = [
            SigmaGenerator(),
            YaraGenerator(),
            SuricataGenerator(),
            SplunkGenerator(),
            ElasticGenerator(),
            DefenderGenerator(),
        ]

    def generate_all(self, threat: ThreatRecord) -> list[GeneratedDetection]:
        return [generator.generate(threat) for generator in self.generators]
