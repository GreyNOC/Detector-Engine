from __future__ import annotations

import pytest
from pydantic import ValidationError

from greynoc_detection_engine.models.cve import CVERecord
from greynoc_detection_engine.models.threat import AIAttackType, ThreatRecord


def test_cve_model_validates_identifier() -> None:
    with pytest.raises(ValidationError):
        CVERecord(cve_id="BAD-1", description="bad")


def test_threat_model_accepts_ai_taxonomy() -> None:
    threat = ThreatRecord(
        title="Prompt injection against support agent",
        summary="Untrusted content changes assistant behavior.",
        category="ai_enabled_threat",
        ai_attack_type=AIAttackType.PROMPT_INJECTION,
    )
    assert threat.ai_attack_type == AIAttackType.PROMPT_INJECTION
    assert threat.status == "new"
