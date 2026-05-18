from __future__ import annotations

from greynoc_detector_engine.models.cve import CVERecord
from greynoc_detector_engine.models.kev import KEVRecord
from greynoc_detector_engine.models.prediction import ForecastHorizon
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
        if threat.attack_forecast is not None:
            forecast = threat.attack_forecast
            if forecast.horizon == ForecastHorizon.IMMINENT:
                actions.append(
                    "Forecast horizon is IMMINENT — open a tracking ticket, enable enhanced "
                    "logging, and brief detection engineering for hunt-now coverage."
                )
            elif forecast.horizon == ForecastHorizon.NEAR_TERM:
                actions.append(
                    "Forecast horizon is NEAR_TERM (≤30d) — schedule a focused hunt within the "
                    "next sprint and confirm patch availability."
                )
            elif forecast.horizon == ForecastHorizon.MID_TERM:
                actions.append(
                    "Forecast horizon is MID_TERM — monitor velocity baselines and re-evaluate "
                    "weekly."
                )
            if forecast.attack_probability >= 0.7:
                actions.append(
                    "Predicted attack probability is high — request emergency change-management "
                    "review for compensating controls."
                )
        if threat.suspected_actors:
            actions.append(
                "Pivot to known actor TTPs ("
                + ", ".join(threat.suspected_actors)
                + ") in your detection backlog."
            )
        if threat.campaign_ids:
            actions.append(
                "Threat is part of an active campaign cluster — share IOCs with peer "
                "SOCs and ISACs."
            )
        return list(dict.fromkeys(actions))
