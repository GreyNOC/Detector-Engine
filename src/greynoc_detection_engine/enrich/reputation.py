from __future__ import annotations

from greynoc_detection_engine.models.source import SourceConfig, SourceReliability


def source_confidence(source: SourceConfig) -> float:
    return {
        SourceReliability.VERIFIED: 0.9,
        SourceReliability.HIGH: 0.8,
        SourceReliability.MEDIUM: 0.55,
        SourceReliability.LOW: 0.3,
    }[source.reliability]
