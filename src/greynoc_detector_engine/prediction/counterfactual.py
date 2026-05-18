"""What-if reasoning over the predictive engine.

Given a threat and its current PredictiveContext, simulate the forecast
under hypothetical interventions:

  * ``patch_applied``: vendor patch reaches GA → CVSS pressure decays,
    public_exploit_availability decays, recency reset.
  * ``ioc_blocked``: organization blocks known C2 infrastructure →
    osint_ioc_corroboration goes to zero.
  * ``segmented``: at-risk asset is taken off the internet →
    we treat exposure as if it became internal-only, reducing the
    feature value the asset bridge fed in.

This is the foundation of "what if I do X tomorrow" decisions and it costs
nothing except a re-score against the same forecaster.
"""

from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from greynoc_detector_engine.models.prediction import AttackForecast
from greynoc_detector_engine.prediction.attack_forecast import AttackForecaster
from greynoc_detector_engine.prediction.features import PredictiveContext


class Intervention(StrEnum):
    PATCH_APPLIED = "patch_applied"
    IOC_BLOCKED = "ioc_blocked"
    SEGMENTED = "segmented"
    DETECTION_DEPLOYED = "detection_deployed"


class CounterfactualResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    intervention: Intervention
    baseline_probability: float = Field(ge=0.0, le=1.0)
    counterfactual_probability: float = Field(ge=0.0, le=1.0)
    probability_delta: float
    horizon_before: str
    horizon_after: str
    rationale: list[str] = Field(default_factory=list)


class CounterfactualEngine:
    """Re-runs the forecaster on perturbed contexts."""

    def __init__(self, forecaster: AttackForecaster | None = None) -> None:
        self.forecaster = forecaster or AttackForecaster()

    def evaluate(
        self,
        ctx: PredictiveContext,
        interventions: Iterable[Intervention],
    ) -> list[CounterfactualResult]:
        baseline: AttackForecast = self.forecaster.forecast(ctx)
        out: list[CounterfactualResult] = []
        for intervention in interventions:
            altered_ctx = self._apply(ctx, intervention)
            cf: AttackForecast = self.forecaster.forecast(altered_ctx)
            out.append(
                CounterfactualResult(
                    intervention=intervention,
                    baseline_probability=baseline.attack_probability,
                    counterfactual_probability=cf.attack_probability,
                    probability_delta=round(cf.attack_probability - baseline.attack_probability, 4),
                    horizon_before=baseline.horizon.value,
                    horizon_after=cf.horizon.value,
                    rationale=self._rationale_for(intervention),
                )
            )
        return out

    def _apply(self, ctx: PredictiveContext, intervention: Intervention) -> PredictiveContext:
        if intervention == Intervention.PATCH_APPLIED:
            # Patch removes the active-exploitation lane and resets EPSS proxy.
            return ctx.model_copy(
                update={
                    "epss": None,
                    "local_intrusion_pressure": 0.0,
                    "kev": None,
                }
            )
        if intervention == Intervention.IOC_BLOCKED:
            # Clear observed indicators on a copy of the threat.
            blocked_threat = ctx.threat.model_copy(update={"observed_indicators": []})
            return ctx.model_copy(update={"threat": blocked_threat})
        if intervention == Intervention.SEGMENTED:
            # Treat exposure as internal-only by removing affected_products
            # entirely; the predictive features fall back to defaults.
            isolated_threat = ctx.threat.model_copy(update={"affected_products": []})
            return ctx.model_copy(
                update={
                    "threat": isolated_threat,
                    "local_intrusion_pressure": ctx.local_intrusion_pressure * 0.25,
                }
            )
        if intervention == Intervention.DETECTION_DEPLOYED:
            # A confirmed detection doesn't change the probability of attack
            # but does shorten the time-to-detect; we model it as a small
            # boost to confidence and zero out chatter-driven hazard by
            # clearing source_items.
            return ctx.model_copy(update={"source_items": []})
        return ctx

    @staticmethod
    def _rationale_for(intervention: Intervention) -> list[str]:
        return {
            Intervention.PATCH_APPLIED: [
                "Vendor patch applied: KEV pressure and EPSS prior removed for this asset.",
                "Local intrusion pressure suppressed since the exploit path is closed.",
            ],
            Intervention.IOC_BLOCKED: [
                "Known IOCs blocked at perimeter; OSINT corroboration drops to zero.",
            ],
            Intervention.SEGMENTED: [
                "Affected asset removed from the network; target-likelihood collapses.",
            ],
            Intervention.DETECTION_DEPLOYED: [
                "Detection deployed: signal collection improves but probability stays similar.",
            ],
        }[intervention]
