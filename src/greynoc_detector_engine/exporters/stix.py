"""Minimal STIX 2.1 bundle exporter.

We render each ThreatRecord as one of:
  * vulnerability  (when the threat has at least one related CVE)
  * indicator      (when the threat has observed_indicators)
  * report         (always — the human-readable wrapper)

Plus one campaign object per CampaignCluster, one threat-actor per
suspected actor, and SCO objects (ipv4-addr, domain-name, url, file)
for every observed indicator. Relationships connect everything.

The output is a STIX 2.1 ``bundle`` JSON object — round-trippable into
MISP, OpenCTI, and any commercial TIP that ingests STIX 2.1.

We deliberately keep the dependency surface to zero (no ``stix2`` lib)
so this stays a pure stdlib build. The schema we emit is the canonical
subset that real consumers actually require; extension fields are
namespaced under ``x_greynoc_*``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from pydantic import BaseModel, ConfigDict, Field

from greynoc_detector_engine.models.indicator import IndicatorType
from greynoc_detector_engine.models.prediction import CampaignCluster
from greynoc_detector_engine.models.threat import ThreatRecord

_STIX_NAMESPACE = NAMESPACE_URL


def _stix_id(prefix: str, key: str) -> str:
    return f"{prefix}--{uuid5(_STIX_NAMESPACE, f'greynoc:{prefix}:{key}')}"


def _now_iso() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def _confidence_int(value: float) -> int:
    return max(0, min(100, round(value * 100)))


class StixBundle(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str = "bundle"
    id: str
    objects: list[dict[str, Any]] = Field(default_factory=list)


class StixExporter:
    """Translate our threat library into a STIX 2.1 bundle."""

    def export(
        self,
        threats: list[ThreatRecord],
        *,
        campaigns: list[CampaignCluster] | None = None,
    ) -> StixBundle:
        objects: list[dict[str, Any]] = []
        identity_id = _stix_id("identity", "engine")
        objects.append(self._identity(identity_id))

        threat_to_stix: dict[str, str] = {}
        for threat in threats:
            objects.extend(self._threat_objects(threat, identity_id, threat_to_stix))
            objects.extend(self._indicator_objects(threat, identity_id, threat_to_stix))

        if campaigns:
            for cluster in campaigns:
                objects.extend(self._campaign_objects(cluster, identity_id, threat_to_stix))

        bundle_id = f"bundle--{uuid5(_STIX_NAMESPACE, 'greynoc:bundle:' + _now_iso())}"
        return StixBundle(id=bundle_id, objects=objects)

    # -- builders ------------------------------------------------------------

    @staticmethod
    def _identity(identity_id: str) -> dict[str, Any]:
        now = _now_iso()
        return {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": now,
            "modified": now,
            "name": "GreyNOC Detection Engine",
            "identity_class": "system",
        }

    def _threat_objects(
        self,
        threat: ThreatRecord,
        identity_id: str,
        threat_to_stix: dict[str, str],
    ) -> list[dict[str, Any]]:
        now = _now_iso()
        objects: list[dict[str, Any]] = []

        # Always a report — human wrapper.
        report_id = _stix_id("report", threat.threat_id)
        threat_to_stix[threat.threat_id] = report_id
        confidence = (
            _confidence_int(threat.attack_forecast.attack_probability)
            if threat.attack_forecast is not None
            else _confidence_int(threat.confidence)
        )
        labels = ["greynoc-threat", threat.category]
        if threat.ai_attack_type:
            labels.append(threat.ai_attack_type.value)
        report = {
            "type": "report",
            "spec_version": "2.1",
            "id": report_id,
            "created_by_ref": identity_id,
            "created": now,
            "modified": now,
            "name": threat.title[:255],
            "description": threat.summary[:4096],
            "published": now,
            "report_types": ["threat-report"],
            "labels": labels,
            "confidence": confidence,
            "object_refs": [],
            "x_greynoc_severity": threat.severity.value,
            "x_greynoc_threat_id": threat.threat_id,
        }
        objects.append(report)

        # Vulnerability objects per CVE.
        for cve_id in threat.related_cves:
            vuln_id = _stix_id("vulnerability", cve_id)
            objects.append(
                {
                    "type": "vulnerability",
                    "spec_version": "2.1",
                    "id": vuln_id,
                    "created_by_ref": identity_id,
                    "created": now,
                    "modified": now,
                    "name": cve_id,
                    "external_references": [{"source_name": "cve", "external_id": cve_id}],
                }
            )
            report["object_refs"].append(vuln_id)  # type: ignore[attr-defined]
            objects.append(
                self._relationship(
                    identity_id,
                    "related-to",
                    report_id,
                    vuln_id,
                    f"Threat report references {cve_id}.",
                )
            )

        # Forecast → x-greynoc-forecast extension on the report.
        if threat.attack_forecast is not None:
            report["x_greynoc_forecast"] = {
                "probability": threat.attack_forecast.attack_probability,
                "horizon": threat.attack_forecast.horizon.value,
                "horizon_days_p50": threat.attack_forecast.horizon_days_p50,
                "horizon_days_p90": threat.attack_forecast.horizon_days_p90,
                "confidence": threat.attack_forecast.confidence.value,
            }

        return objects

    def _indicator_objects(
        self,
        threat: ThreatRecord,
        identity_id: str,
        threat_to_stix: dict[str, str],
    ) -> list[dict[str, Any]]:
        if not threat.observed_indicators:
            return []
        now = _now_iso()
        objects: list[dict[str, Any]] = []
        report_id = threat_to_stix.get(threat.threat_id)
        for indicator in threat.observed_indicators:
            pattern = self._stix_pattern(indicator.value, indicator.type)
            if pattern is None:
                continue
            ind_id = _stix_id("indicator", f"{indicator.type.value}:{indicator.value}")
            objects.append(
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": ind_id,
                    "created_by_ref": identity_id,
                    "created": now,
                    "modified": now,
                    "indicator_types": ["malicious-activity"],
                    "name": f"GreyNOC observed {indicator.type.value}",
                    "pattern": pattern,
                    "pattern_type": "stix",
                    "valid_from": now,
                    "confidence": _confidence_int(indicator.confidence),
                    "x_greynoc_source": indicator.source or "engine",
                }
            )
            if report_id is not None:
                objects.append(
                    self._relationship(
                        identity_id,
                        "indicates",
                        ind_id,
                        report_id,
                        "Indicator observed in association with this threat.",
                    )
                )
        return objects

    def _campaign_objects(
        self,
        cluster: CampaignCluster,
        identity_id: str,
        threat_to_stix: dict[str, str],
    ) -> list[dict[str, Any]]:
        now = _now_iso()
        objects: list[dict[str, Any]] = []
        camp_id = _stix_id("campaign", cluster.campaign_id)
        objects.append(
            {
                "type": "campaign",
                "spec_version": "2.1",
                "id": camp_id,
                "created_by_ref": identity_id,
                "created": now,
                "modified": now,
                "name": cluster.label[:255],
                "description": " ".join(cluster.reasons)[:4096],
                "first_seen": (cluster.first_seen.isoformat() if cluster.first_seen else now),
                "last_seen": (cluster.last_seen.isoformat() if cluster.last_seen else now),
                "x_greynoc_velocity": cluster.velocity_score,
                "x_greynoc_cohesion": cluster.cohesion,
            }
        )
        for tid in cluster.related_threat_ids:
            stix_ref = threat_to_stix.get(tid)
            if stix_ref is None:
                continue
            objects.append(
                self._relationship(
                    identity_id,
                    "related-to",
                    camp_id,
                    stix_ref,
                    "Threat belongs to this campaign cluster.",
                )
            )
        for actor in cluster.suspected_actors:
            actor_id = _stix_id("threat-actor", actor)
            objects.append(
                {
                    "type": "threat-actor",
                    "spec_version": "2.1",
                    "id": actor_id,
                    "created_by_ref": identity_id,
                    "created": now,
                    "modified": now,
                    "name": actor,
                }
            )
            objects.append(
                self._relationship(
                    identity_id,
                    "attributed-to",
                    camp_id,
                    actor_id,
                    "Campaign attributed to threat actor by public reporting.",
                )
            )
        return objects

    @staticmethod
    def _relationship(
        identity_id: str,
        relationship_type: str,
        source_ref: str,
        target_ref: str,
        description: str,
    ) -> dict[str, Any]:
        now = _now_iso()
        rel_id = _stix_id("relationship", f"{source_ref}:{relationship_type}:{target_ref}")
        return {
            "type": "relationship",
            "spec_version": "2.1",
            "id": rel_id,
            "created_by_ref": identity_id,
            "created": now,
            "modified": now,
            "relationship_type": relationship_type,
            "source_ref": source_ref,
            "target_ref": target_ref,
            "description": description[:512],
        }

    @staticmethod
    def _stix_pattern(value: str, indicator_type: IndicatorType) -> str | None:
        # Escape single quotes for STIX patterning grammar.
        safe = value.replace("'", "")
        if indicator_type == IndicatorType.IPV4:
            return f"[ipv4-addr:value = '{safe}']"
        if indicator_type == IndicatorType.IPV6:
            return f"[ipv6-addr:value = '{safe}']"
        if indicator_type == IndicatorType.DOMAIN:
            return f"[domain-name:value = '{safe}']"
        if indicator_type == IndicatorType.URL:
            return f"[url:value = '{safe}']"
        if indicator_type == IndicatorType.FILE_HASH:
            # Heuristic: pick the algorithm by length.
            algo = (
                "SHA-256"
                if len(safe) == 64
                else "SHA-1"
                if len(safe) == 40
                else "MD5"
                if len(safe) == 32
                else "SHA-256"
            )
            return f"[file:hashes.'{algo}' = '{safe}']"
        return None
