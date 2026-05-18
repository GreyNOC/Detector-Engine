from __future__ import annotations

from greynoc_detector_engine.enrich.reputation import IndicatorReputation
from greynoc_detector_engine.models.cve import CVERecord
from greynoc_detector_engine.models.kev import KEVRecord
from greynoc_detector_engine.models.prediction import EPSSScore, PredictionFingerprint
from greynoc_detector_engine.models.threat import ThreatRecord
from greynoc_detector_engine.utils.hashing import canonical_json_hash

_VOLATILE_THREAT_FIELDS = {
    "attack_forecast",
    "predictive_score",
    "exploitability_score",
    "early_warning_score",
    "ai_abuse_score",
    "recommended_soc_actions",
    "generated_detections",
    "changelog",
    "summary",
    "severity",
    "epss_scores",
    "suspected_actors",
    "campaign_ids",
}


def reputation_watermark(reputations: list[IndicatorReputation]) -> str:
    payload = [
        rep.model_dump(mode="json", exclude_none=True)
        for rep in sorted(reputations, key=lambda item: (item.type.value, item.value.lower()))
    ]
    return canonical_json_hash(payload, length=24)


def build_prediction_fingerprint(
    *,
    threat: ThreatRecord,
    cve: CVERecord | None,
    kev: KEVRecord | None,
    epss: EPSSScore | None,
    source_watermark: str,
    reputation_watermark_value: str,
    model_version: str,
    config_hash: str,
) -> PredictionFingerprint:
    threat_payload = threat.model_dump(
        mode="json",
        exclude=_VOLATILE_THREAT_FIELDS,
        exclude_none=True,
    )
    payload = {
        "threat": threat_payload,
        "cve": cve.model_dump(mode="json", exclude_none=True) if cve else None,
        "kev": kev.model_dump(mode="json", exclude_none=True) if kev else None,
        "epss": epss.model_dump(mode="json", exclude_none=True) if epss else None,
        "source_watermark": source_watermark,
        "reputation_watermark": reputation_watermark_value,
        "model_version": model_version,
        "config_hash": config_hash,
    }
    return PredictionFingerprint(
        threat_id=threat.threat_id,
        fingerprint=canonical_json_hash(payload, length=32),
        model_version=model_version,
        source_watermark=source_watermark,
        reputation_watermark=reputation_watermark_value,
        config_hash=config_hash,
    )
