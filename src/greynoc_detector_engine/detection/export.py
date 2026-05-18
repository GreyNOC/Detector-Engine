from __future__ import annotations

from collections import defaultdict
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from greynoc_detector_engine.models.detection import (
    DetectionKind,
    DetectionStatus,
    GeneratedDetection,
)

ExportFormat = Literal["json", "text"]


class DetectionExportBundle(BaseModel):
    model_config = ConfigDict(extra="forbid")

    bundle_name: str
    status_filter: DetectionStatus
    count: int
    detections_by_kind: dict[str, int] = Field(default_factory=dict)
    detections: list[GeneratedDetection] = Field(default_factory=list)


def build_detection_export_bundle(
    detections: list[GeneratedDetection],
    *,
    status: DetectionStatus = DetectionStatus.VALIDATED,
    kind: DetectionKind | None = None,
    threat_id: str | None = None,
    bundle_name: str = "greynoc-validated-detections",
) -> DetectionExportBundle:
    filtered = [detection for detection in detections if detection.status == status]
    if kind is not None:
        filtered = [detection for detection in filtered if detection.kind == kind]
    if threat_id is not None:
        filtered = [detection for detection in filtered if detection.related_threat_id == threat_id]

    by_kind: defaultdict[str, int] = defaultdict(int)
    for detection in filtered:
        by_kind[detection.kind.value] += 1

    return DetectionExportBundle(
        bundle_name=bundle_name,
        status_filter=status,
        count=len(filtered),
        detections_by_kind=dict(sorted(by_kind.items())),
        detections=filtered,
    )


def render_detection_export_bundle(
    bundle: DetectionExportBundle,
    *,
    export_format: ExportFormat,
) -> str:
    if export_format == "json":
        return bundle.model_dump_json(indent=2)
    sections = [
        f"# {bundle.bundle_name}",
        "",
        f"Status: {bundle.status_filter.value}",
        f"Detection count: {bundle.count}",
        "",
    ]
    for detection in bundle.detections:
        sections.extend(
            [
                f"## {detection.title}",
                f"ID: {detection.detection_id}",
                f"Kind: {detection.kind.value}",
                f"Threat: {detection.related_threat_id}",
                f"Confidence: {detection.confidence:.2f}",
                "",
                "Required telemetry:",
                *(f"- {item}" for item in detection.required_telemetry),
                "",
                "Rule/query:",
                "```",
                detection.rule_query,
                "```",
                "",
                "Validation evidence:",
                *(
                    f"- {item.result.value}: {item.summary}"
                    for item in detection.validation_evidence
                ),
                "",
            ]
        )
    return "\n".join(sections)
