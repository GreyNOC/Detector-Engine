from __future__ import annotations

import pytest
import typer

from greynoc_detector_engine.cli.main import (
    _count_by_value,
    _detection_summary,
    _parse_enum,
    _threat_priority_sort_key,
)
from greynoc_detector_engine.models.detection import (
    DetectionKind,
    DetectionStatus,
    GeneratedDetection,
)
from greynoc_detector_engine.models.threat import ThreatSeverity


def test_count_by_value() -> None:
    assert _count_by_value(["high", "low", "high"]) == {"high": 2, "low": 1}


def test_parse_enum_accepts_valid_value() -> None:
    assert _parse_enum(ThreatSeverity, "critical", "severity") == ThreatSeverity.CRITICAL


def test_parse_enum_rejects_invalid_value() -> None:
    with pytest.raises(typer.BadParameter) as exc_info:
        _parse_enum(ThreatSeverity, "urgent", "severity")

    assert "Expected one of" in str(exc_info.value)


def test_detection_summary_is_compact() -> None:
    detection = GeneratedDetection(
        related_threat_id="thr-example",
        kind=DetectionKind.SIGMA,
        status=DetectionStatus.DRAFT,
        title="Example detection",
        description="Example defensive detection",
        query="selection: example",
        required_logs=["process_creation"],
        confidence=0.7,
    )

    summary = _detection_summary(detection)

    assert summary["related_threat_id"] == "thr-example"
    assert summary["kind"] == "sigma"
    assert summary["status"] == "draft"
    assert summary["required_telemetry"] == ["process_creation"]
    assert "rule_query" not in summary


def test_threat_priority_sort_key_orders_by_probability_first() -> None:
    lower = {"attack_probability": 0.4, "severity": "critical", "predictive_score": 99.0}
    higher = {"attack_probability": 0.8, "severity": "low", "predictive_score": 1.0}

    assert _threat_priority_sort_key(higher) > _threat_priority_sort_key(lower)
