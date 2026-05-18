# GreyNOC Exclusive Engine Upgrade Path

This document defines the upgrade path for making GreyNOC Detector Engine a
leading-edge detection platform with defensible, GreyNOC-specific capabilities.

## Strategic Position

GreyNOC should not compete as a generic rule generator. The strongest position is
an evidence-gated detection intelligence engine that turns public and internal
signals into trusted, explainable, validated detection assets.

The product promise:

> GreyNOC does not just generate detections. GreyNOC proves which detections are
> worth trusting.

## Exclusive Feature Set

### 1. GreyNOC Signal DNA

Signal DNA creates a stable fingerprint for a threat and grades the strength of
the signal behind it.

Inputs:

- Source references
- CVE count
- KEV count
- Detection opportunities
- AI relevance
- SOC action density
- Affected products
- ATT&CK/TTP terms

Outputs:

- `gndna-*` fingerprint
- Signal strength: weak, moderate, strong, exceptional
- Evidence density
- Recommended-action density
- Signature terms

Why it matters:

- Gives GreyNOC proprietary language around threat identity.
- Helps analysts compare recurring or similar threats.
- Enables future clustering, deduplication, and campaign tracking.

### 2. Detection Quality Passport

The Detection Quality Passport gives every detection a trust score and grade.

Grades:

- Unproven
- Bronze
- Silver
- Gold
- Platinum

Inputs:

- Detection status
- Passed validation evidence
- Reviewer presence
- Telemetry source presence
- Positive sample size
- Precision-ready test report
- True-positive and false-positive counts

Why it matters:

- Makes detection trust measurable.
- Gives SOC leaders a simple way to separate draft ideas from reliable assets.
- Creates a defensible quality layer competitors cannot easily copy.

### 3. Evidence-Gated Promotion

A detection cannot become validated without passed evidence. Current gate:

- At least one passed evidence item
- Telemetry source required
- Reviewer required
- Positive sample size required

Next gate:

- Precision-ready test report required before validation
- False-positive budget must be below backend-specific threshold
- Evidence must map to a telemetry schema

### 4. Precision-Ready Test Reports

The test harness evaluates positive and negative fixtures and reports whether a
detection is precision-ready.

Next evolution:

- Persist test reports
- Link test reports to validation evidence
- Require precision-ready test reports for validated status
- Add backend-aware evaluators for Sigma, Splunk, Elastic, and Defender first

### 5. Trusted Export Bundles

Exports should default to validated detections and include quality context.

Current export includes:

- Detection content
- Rule/query
- Required telemetry
- Validation evidence
- Counts by detection kind

Next export should include:

- Detection Quality Passport
- Signal DNA reference
- ATT&CK mappings
- Backend-specific deployment notes
- Tuning guidance

## Upgrade Roadmap

### Phase A: Trust Core

Status: partially implemented.

- Signal DNA
- Detection Quality Passport
- Evidence-gated validation
- Detection fixture test harness
- Validated export bundles

Next tasks:

1. Persist detection test reports.
2. Add quality passport to exports.
3. Require precision-ready test reports for validation.
4. Add API endpoints for batch passports and batch Signal DNA.

### Phase B: Backend-Aware Detection Quality

Goal: move from text-level fixture testing to backend-specific validation.

Tasks:

1. Add Sigma evaluator.
2. Add Splunk SPL evaluator.
3. Add Elastic KQL evaluator.
4. Add Defender KQL evaluator.
5. Add backend-specific field assumptions.
6. Add false-positive budget by backend.

### Phase C: Threat Clustering and Campaign Memory

Goal: use Signal DNA to track related threats over time.

Tasks:

1. Cluster threats by Signal DNA signature overlap.
2. Track recurring source patterns.
3. Identify rising campaigns based on score-event changes.
4. Add campaign records and campaign-level recommendations.

### Phase D: Asset-Aware Prioritization

Goal: move beyond global risk into local business risk.

Tasks:

1. Add asset inventory import model.
2. Map affected products to assets.
3. Add business criticality.
4. Add exposure context.
5. Recalculate risk using local environment context.

### Phase E: AI-Native SOC Intelligence

Goal: become the strongest defensive AI-era detection engine.

Tasks:

1. Expand AI attack taxonomy mappings.
2. Add AI-specific telemetry expectations.
3. Add safe AI detection explanations.
4. Add prompt-injection and agent-abuse detection templates.
5. Add AI supply-chain detection packs.

## Engineering Rule

Do not add features that only increase rule volume. Prioritize features that
increase trust, evidence, precision, explainability, and SOC actionability.

## Near-Term Build Order

1. Persist detection test reports.
2. Add Quality Passport to export bundles.
3. Require precision-ready test reports for validation.
4. Add backend-aware Sigma evaluator.
5. Add backend-aware Splunk evaluator.
6. Add Signal DNA clustering prototype.
7. Add asset inventory model.
8. Add local risk overlay.
