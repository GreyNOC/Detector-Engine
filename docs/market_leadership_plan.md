# GreyNOC Detector Engine Market Leadership Plan

This plan turns GreyNOC Detector Engine from a strong defensive detection
workbench into a market-leading detection engineering platform.

## North Star

GreyNOC should become the engine SOC teams trust to convert messy external
signals into validated, explainable, low-noise detections across SIEM, EDR,
cloud, identity, network, and AI-security telemetry.

The differentiator is not generating the most rules. The differentiator is
validated detections with transparent evidence, scoring, telemetry requirements,
false-positive controls, and operational context.

## Product Principles

1. Defensive-only by design: never generate exploit code, payloads, bypasses, or
   abuse-enabling procedures.
2. Evidence first: every score, detection, and recommendation must point back to
   source evidence and explainable signals.
3. Draft is not validated: generated detections remain draft until tested
   against representative telemetry.
4. Analyst control: the engine recommends and automates repetitive work, but SOC
   operators approve promotion to validated status.
5. Low noise beats broad coverage: detection quality is measured by precision,
   explainability, coverage, and response value.

## Current State

The engine now has:

- Fixture-first ingest for CVE, KEV, RSS, and GitHub metadata.
- Source-run history.
- SQLite storage for CVEs, KEV entries, raw source items, threats, detections,
  source runs, and score events.
- Correlation from CVEs to KEV, source references, exploit references, and AI
  attack terms.
- Explainable exploitability, AI-abuse, early-warning, and risk scoring.
- Optional enrichment fields for EPSS, exploit maturity, patch availability,
  internet exposure, and asset exposure.
- Draft detection generation for Sigma, Splunk, Elastic, Defender, YARA
  metadata-only, and Suricata metadata-only formats.
- Protected mutating API routes using an optional API key.
- Fixture path traversal protection.
- Safer HTTP fetching with retries, response-size limits, scheme validation, and
  optional host allowlists.
- Docker hardening and CI quality gates.
- A detection lifecycle endpoint to promote detections to validated or
  deprecated status.

## Phase 1: Reliability and Validation Foundation

Goal: make the engine safe, testable, and dependable enough for continuous SOC
usage.

Deliverables:

- Increase unit and integration coverage across ingest, correlation, scoring,
  detection generation, API auth, fixture safety, and storage migrations.
- Add CI coverage thresholds and fail builds on coverage regressions.
- Add structured JSON logging for ingest, scoring, correlation, and API actions.
- Add audit events for mutating API calls.
- Add deterministic fixture datasets covering high, medium, low, and false-positive
  scenarios.
- Add migration tests for SQLite payload compatibility.
- Add release packaging and versioned changelog.

Exit criteria:

- CI passes consistently.
- Coverage target is enforced.
- Every mutating action emits an audit event.
- Existing fixtures cover at least five realistic threat scenarios.

## Phase 2: Enrichment and Risk Intelligence

Goal: make risk scoring better than basic CVSS prioritization.

Deliverables:

- EPSS enrichment adapter.
- CISA KEV freshness tracking.
- Vendor advisory enrichment.
- Patch availability and exploit maturity enrichment.
- Asset inventory import interface.
- Internet exposure and business criticality scoring.
- Affected-product popularity and prevalence enrichment.
- Score calibration dashboard or reports.

Exit criteria:

- Risk score explains CVSS, EPSS, KEV, exploit maturity, patch status, asset
  exposure, and business impact.
- SOC users can distinguish internet-exposed critical risk from theoretical
  severity.
- Score history can show why a threat moved up or down.

## Phase 3: Detection Quality Engine

Goal: make generated detections usable, testable, and tunable.

Deliverables:

- Detection test harness with positive and negative fixtures.
- Telemetry schema mapping for major targets: Sigma backends, Splunk, Elastic,
  Microsoft Defender, Suricata, YARA, cloud logs, identity logs, and EDR events.
- False-positive suppression templates.
- Detection confidence scoring based on telemetry specificity, source quality,
  and validation evidence.
- Detection promotion workflow requiring validation evidence before `validated`.
- Detection deprecation workflow with reason tracking.
- ATT&CK and D3FEND mapping support.

Exit criteria:

- Detections have test evidence.
- Draft detections cannot be promoted without a validation note or evidence.
- Generated rules include backend-specific field assumptions and tuning guidance.

## Phase 4: SOC Workflow Integrations

Goal: fit naturally into the tools SOC teams already use.

Deliverables:

- SIEM export packs for Splunk, Elastic, Sentinel/Defender, and Sigma.
- Case/ticket export for Jira, GitHub Issues, or other workflow systems.
- Webhook notifications for high-confidence/high-risk threat updates.
- API pagination, filtering, and search.
- Postgres storage backend for multi-user deployments.
- Authentication and RBAC beyond single API key.
- Multi-tenant workspace model if GreyNOC serves multiple customers.

Exit criteria:

- SOC teams can ingest, triage, validate, export, and track detections without
  manual copy/paste.
- Multi-user deployments have real auth, roles, audit logs, and durable storage.

## Phase 5: AI-Native Detection Engineering

Goal: make GreyNOC excellent at AI-era threat detection without crossing safety
boundaries.

Deliverables:

- AI attack taxonomy mapped to observed defensive telemetry.
- Prompt-injection, agent abuse, tool misuse, RAG poisoning, model supply-chain,
  and synthetic identity detection opportunities.
- Safe explanation layer that summarizes detection logic without providing
  exploitation steps.
- Analyst copilot features for tuning, summarizing, and mapping detections.
- Evaluation harness for hallucination, unsafe output, and detection quality.

Exit criteria:

- AI-security detections remain defensive, explainable, and telemetry-grounded.
- Safety tests block offensive or abuse-enabling output.
- Analysts can ask why a detection exists and get source-backed explanations.

## Phase 6: Market Differentiators

Goal: make GreyNOC hard to copy.

Differentiators:

- Explainable multi-signal risk scoring, not CVSS-only prioritization.
- Validated detection lifecycle, not generic rule generation.
- Defensive-only GitHub metadata monitoring that avoids unsafe code execution.
- AI-enabled threat taxonomy built into normalization and scoring.
- Evidence-backed SOC recommendations.
- Cross-backend rule generation with telemetry requirements and validation steps.
- A local-first deployment path for sensitive environments.

## Metrics That Matter

Track these as product KPIs:

- Mean time from source signal to draft detection.
- Mean time from draft detection to validated detection.
- True-positive validation rate.
- False-positive rate by detection kind and backend.
- Number of validated detections by ATT&CK tactic/technique.
- Percentage of high-risk threats with asset-exposure context.
- Percentage of detections with test fixtures.
- Analyst acceptance rate.
- Detections deprecated due to noise or stale logic.

## Immediate Next Engineering Backlog

1. Run CI and fix any ruff, mypy, or pytest failures from the latest hardening
   commits.
2. Add validation evidence fields to `GeneratedDetection`.
3. Add an EPSS enrichment adapter and fixture.
4. Add API filters for detections by status, kind, and threat ID.
5. Add score-event API endpoints for historical scoring visibility.
6. Add Postgres storage implementation behind the storage protocol.
7. Add RBAC-ready auth abstraction.
8. Add export bundles for validated detections.
9. Add detection test fixture format and runner.
10. Add a release workflow that builds and tests Docker images.
