from __future__ import annotations

from greynoc_detector_engine.models.cve import CVERecord
from greynoc_detector_engine.models.kev import KEVRecord
from greynoc_detector_engine.models.threat import ThreatRecord


class SOCRecommendationBuilder:
    def recommend(
        self,
        threat: ThreatRecord,
        *,
        cve: CVERecord | None = None,
        kev: KEVRecord | None = None,
    ) -> list[str]:
        actions = list(threat.recommended_soc_actions)
        if kev:
            actions.extend(
                [
                    "Prioritize remediation for internet-facing affected assets.",
                    "Review CISA required action and internal exception handling.",
                ]
            )
        if cve and cve.cvss_score and cve.cvss_score >= 9:
            actions.append(
                "Treat high-CVSS exposure as patch-priority until compensating controls "
                "are confirmed."
            )
        if threat.ai_attack_type:
            actions.append(
                "Review AI application logs for untrusted content paths and tool-call boundaries."
            )
        return list(dict.fromkeys(actions))
