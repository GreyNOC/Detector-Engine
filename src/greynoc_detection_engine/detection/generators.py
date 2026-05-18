from __future__ import annotations

from typing import Protocol

from greynoc_detection_engine.detection.defender_generator import DefenderGenerator
from greynoc_detection_engine.detection.elastic_generator import ElasticGenerator
from greynoc_detection_engine.detection.sigma_generator import SigmaGenerator
from greynoc_detection_engine.detection.splunk_generator import SplunkGenerator
from greynoc_detection_engine.detection.suricata_generator import SuricataGenerator
from greynoc_detection_engine.detection.yara_generator import YaraGenerator
from greynoc_detection_engine.models.detection import GeneratedDetection
from greynoc_detection_engine.models.threat import ThreatRecord


class DetectionGenerator(Protocol):
    def generate(self, threat: ThreatRecord) -> GeneratedDetection: ...


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
