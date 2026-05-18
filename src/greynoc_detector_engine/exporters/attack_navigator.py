"""MITRE ATT&CK Navigator layer exporter.

Given the engine's threat library, produce a Navigator JSON layer whose
techniques are colored by aggregate predictive score. SOC dashboards
that already speak Navigator can drop the layer in and see "where the
engine thinks the next attack is coming from" without any new tooling.

We use MitreAttackInferrer to derive techniques per threat, then weight
each technique by the *max* attack_probability across threats that
reference it. Color scales linearly from green (0.0) to red (1.0).
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from greynoc_detector_engine.enrich.mitre_attack import MitreAttackInferrer
from greynoc_detector_engine.models.threat import ThreatRecord


class NavigatorTechnique(BaseModel):
    model_config = ConfigDict(extra="forbid")

    techniqueID: str
    score: int = Field(ge=0, le=100)
    color: str = ""
    comment: str = ""
    enabled: bool = True


class NavigatorLayer(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = "GreyNOC Predictive Layer"
    versions: dict[str, str] = Field(
        default_factory=lambda: {
            "attack": "14",
            "navigator": "4.9.1",
            "layer": "4.5",
        }
    )
    domain: str = "enterprise-attack"
    description: str = "Heat map colored by maximum predicted attack probability per technique."
    techniques: list[NavigatorTechnique] = Field(default_factory=list)
    gradient: dict[str, Any] = Field(
        default_factory=lambda: {
            "colors": ["#1fb500", "#ffeb3b", "#d32f2f"],
            "minValue": 0,
            "maxValue": 100,
        }
    )
    legendItems: list[dict[str, Any]] = Field(default_factory=list)


class AttackNavigatorExporter:
    """Build a Navigator JSON layer from threats + predictive scores."""

    def __init__(self) -> None:
        self.inferrer = MitreAttackInferrer()

    def export(self, threats: list[ThreatRecord]) -> NavigatorLayer:
        scores: dict[str, float] = defaultdict(float)
        comments: dict[str, list[str]] = defaultdict(list)

        for threat in threats:
            techniques = self._techniques_for_threat(threat)
            if not techniques:
                continue
            probability = (
                threat.attack_forecast.attack_probability
                if threat.attack_forecast is not None
                else float(threat.confidence)
            )
            for tid in techniques:
                if probability > scores[tid]:
                    scores[tid] = probability
                if threat.title and len(comments[tid]) < 5:
                    comments[tid].append(threat.title[:80])

        nav_techs: list[NavigatorTechnique] = []
        for tid, prob in scores.items():
            nav_techs.append(
                NavigatorTechnique(
                    techniqueID=tid,
                    score=round(prob * 100),
                    comment="; ".join(comments[tid]),
                )
            )
        nav_techs.sort(key=lambda t: t.score, reverse=True)

        return NavigatorLayer(techniques=nav_techs)

    def _techniques_for_threat(self, threat: ThreatRecord) -> list[str]:
        # Use any techniques the threat already carries, else infer from text.
        if threat.mitre_attack_mapping:
            return list(threat.mitre_attack_mapping)
        text = " ".join(
            [
                threat.title,
                threat.summary,
                *(ref.raw_excerpt for ref in threat.source_references),
            ]
        )
        return self.inferrer.infer(text)
