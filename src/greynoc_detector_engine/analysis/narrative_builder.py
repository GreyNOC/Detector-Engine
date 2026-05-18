from __future__ import annotations

from greynoc_detector_engine.models.threat import ThreatRecord


class NarrativeBuilder:
    def build(self, threat: ThreatRecord) -> str:
        parts: list[str] = [threat.summary]
        if threat.related_cves:
            parts.append(f"Related CVEs: {', '.join(threat.related_cves)}.")
        if threat.related_kev_entries:
            parts.append("CISA KEV correlation indicates confirmed exploitation pressure.")
        if threat.ai_attack_type:
            parts.append(f"AI attack taxonomy classification: {threat.ai_attack_type.value}.")
        if threat.attack_forecast is not None:
            forecast = threat.attack_forecast
            parts.append(
                f"Predictive forecast: attack probability {forecast.attack_probability:.2f} "
                f"with horizon {forecast.horizon.value} "
                f"(p50 {forecast.horizon_days_p50}d, p90 {forecast.horizon_days_p90}d, "
                f"confidence {forecast.confidence.value})."
            )
        if threat.suspected_actors:
            parts.append(f"Attributed signals to actors: {', '.join(threat.suspected_actors)}.")
        if threat.campaign_ids:
            parts.append(f"Member of campaign clusters: {', '.join(threat.campaign_ids)}.")
        if threat.epss_scores:
            top = threat.epss_scores[0]
            parts.append(f"FIRST.org EPSS prior: {top.epss:.3f} (percentile {top.percentile:.2f}).")
        return " ".join(part for part in parts if part)
