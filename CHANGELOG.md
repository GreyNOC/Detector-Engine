# Changelog

## v1.0.1 - Security hardening patch

This patch release keeps the v1.0 operator workflow intact and tightens the
engine's own attack surface.

### Security

- HTTP ingest redirects are now followed manually so every `Location` hop is
  revalidated against scheme and host policy. Cross-host redirects are refused
  unless the destination is explicitly allowlisted in
  `GREYNOC_ALLOWED_FETCH_HOSTS`.
- Fixture-backed JSON/text ingest now checks file size against
  `GREYNOC_MAX_RESPONSE_BYTES` before reading.
- Dependency floors were raised for the FastAPI/Starlette/Uvicorn runtime
  surface and affected transitive packages surfaced by audit.

### Quality

- Added regression tests for redirect allowlist behavior and fixture size
  bounds.
- Added the PEP 561 `py.typed` marker so source-tree mypy checks can validate
  the package cleanly.
- Verification at release: 167 tests pass, ruff passes, and source-tree mypy
  passes.

## v1.0.0 — Advanced tool, operator-grade workflow

The 1.0 release moves the engine from advanced prototype to advanced
SOC-support tool. It keeps the existing defensive-only safety boundary
intact while making the operator workflow repeatable, auditable, and
evidence-gated.

### Highlights

- **Golden-path demo (`gn workflow demo`).** A single command initializes
  local paths, ingests every bundled fixture source it can find,
  correlates, runs the predictive layer, drafts detections, and prints a
  compact JSON report. Fully offline by default; no network access
  required.
- **Detection validation lifecycle on the CLI.** `gn detections validate`
  refuses to validate without structured evidence (telemetry source,
  reviewer, sample size, true/false positive counts, summary).
  `gn detections reject` deprecates a rule with a documented reason.
  `gn detections quality` reports the quality passport (grade, trust
  score, blockers, strengths).
- **Job history audit trail.** Every orchestrated worker run (ingest,
  correlate, predict, score, generate-detections, workflow demo) is
  captured in a new `job_history` SQLite table via a `record_job`
  context manager. Surfaced through `gn jobs list / show` and the
  `GET /jobs` and `GET /jobs/{id}` API routes. CLI and API runs share
  the same audit trail.
- **API/CLI list-limit consistency.** All list commands default to 100
  results and cap at 500, with clear validation errors on out-of-range
  values.
- **Forecasting performance pipeline.** Calibrated prediction with input
  fingerprinting skips recomputation when inputs haven't changed
  (override with `--force`). New `forecast_runs` and
  `prediction_fingerprints` tables.
- **Documentation refresh.** `docs/cli_operator_guide.md` documents the
  full operator workflow; `docs/advanced_tool_roadmap.md` records the
  advanced-vs-future-work boundary; README quickstart leads with the
  golden-path demo.

### CI / quality

- Ruff format check, ruff lint, strict mypy, and pytest (with coverage)
  all green on every commit.
- 164 tests pass (up from 128 at v0.9.1); coverage 78%.
- Pytest `tests/__init__.py` added so the prediction-performance test
  can import shared fixtures cleanly.

### Defensive boundary (unchanged)

- No exploit / payload / offensive-scanning / evasion / persistence
  capability has been added or relaxed in this release. Detection
  generation remains draft / review-focused with structured evidence
  required for validation.

## v0.9.1 — Predictive, OSINT-driven, defender-first

Released as v0.9.1; v0.9.0 on origin pre-existed from an earlier release.
The semantic content of this version is the v0.9 milestone.

This release turns the reactive aggregator into a forward-looking, fully
explainable predictive engine that also senses the local network, classifies
ICS devices, and exports to the wider defender ecosystem.

### Highlights

- **Predictive forecast** per threat: `AttackForecast { probability, horizon,
  p50/p90 days, confidence, named drivers }`, computed from a 14-feature
  vector and fused via tunable weights in `config/scoring.yaml`.
- **OSINT enrichment** for FIRST.org EPSS, abuse.ch ThreatFox + URLhaus, and
  public ransomware leak-site metadata.
- **ICS module** classifies devices by MAC OUI + protocol port fingerprints
  (Modbus, S7, DNP3, EtherNet/IP, BACnet, OPC UA, IEC 60870-5-104, Profinet,
  FINS, MELSEC, CODESYS). Detection-only; we never speak ICS protocols.
- **Spacestation sensor** reads the OS connection table and detects port
  scans, slow scans, SYN floods, port knocks, ICS probes, darknet touches.
  Adaptive per-host baselines via EWMA mean+variance.
- **Darknet honeypot** — pure-asyncio TCP listener; binds loopback by default,
  per-source token-bucket rate limiter, sanitized + redacted payload preview,
  never speaks any protocol back.
- **Defensive git ingestor** — shallow, allowlisted, sandboxed clones of
  detection-rule repositories (SigmaHQ/sigma, YARA-Rules, signature-base);
  symlinks refused, extension allowlist enforced, content-only.
- **Analyst feedback loop** — `feedback submit` re-tunes fusion weights
  deterministically (per-step cap + renormalization).
- **Forecast accuracy tracker** — Brier score + per-bucket / per-horizon
  calibration from recorded `forecast_outcomes`.
- **Counterfactual analysis** — what-if simulation for `patch_applied`,
  `ioc_blocked`, `segmented`, `detection_deployed`.
- **STIX 2.1 + ATT&CK Navigator exporters** — pure-stdlib, round-trippable
  into MISP / OpenCTI / commercial TIPs.
- **`doctor` CLI** — self-check confirms safety defaults (loopback honeypot,
  HTTP body + redirect caps) and reports per-source ingest health.

### Security hardening (`docs/security_review.md`)

- HTTP client: 50 MiB body cap + 5-hop redirect cap.
- Git clone: `http.followRedirects=false`, per-call random sandbox directory,
  `HOME` redirected, no userinfo, no SSH/file/git URIs.
- Repo walker: refuses symlinks, contains every path under the resolved
  root, forbidden-extension blocklist.
- Honeypot: defaults to `127.0.0.1`, explicit `allow_external_bind`
  required for non-loopback binds, per-source rate limit, high-entropy
  redaction on payload preview.
- API: `/ingest?fixture=...` and `/predict/run?asset_inventory=...` only
  accept paths inside `data_dir` (or `$GREYNOC_FIXTURE_DIR`).
- Detection generators: rule terms are sanitized via
  `detection/safety.py::sanitize_rule_term`.
- `PredictiveContext`: removed `arbitrary_types_allowed=True`.

### Storage

- SQLite is opened in WAL mode with `synchronous=NORMAL` + 256 MiB mmap.
- Schema is versioned via `PRAGMA user_version`; migrations live in
  `src/greynoc_detector_engine/storage/migrations.py`
  (current version 4).
- New tables: `epss_scores`, `campaigns`, `attack_forecasts`,
  `indicator_reputation`, `assets`, `target_likelihoods`, `network_devices`,
  `ics_observations`, `intrusion_signals`, `honeypot_events`,
  `threat_feedback`, `scan_baselines`, `source_health`, `forecast_outcomes`.

### Quality gate

- `ruff check` and `ruff format --check` pass.
- `mypy --strict` passes on the source tree.
- `pytest`: 91 tests pass (25 new across security, prediction, network,
  ICS, spacestation, exporters, migrations, doctor).

## v0.9.0 — 2026-05-18

First near-production evaluation release for the defensive detection-engine
foundation.

### Added

- Fixture-first CVE, CISA KEV, RSS, and GitHub metadata ingestion.
- SQLite-backed storage for raw items, CVEs, KEV entries, threats,
  detections, source runs, and score events.
- Explainable exploitability, risk, early-warning, AI-abuse, and signal
  scoring.
- EPSS enrichment using local fixtures or the FIRST EPSS API when live
  fetching is deliberately enabled.
- Detection generation for Sigma, Splunk SPL, Elastic KQL, Microsoft
  Defender KQL, YARA metadata-only, and Suricata metadata-only outputs.
- Evidence-gated detection lifecycle workflow for validated and deprecated
  detection states.
- Detection export bundles for validated detection handoff.
- Detection test harness for positive and negative fixture checks.
- Score-event history API.
- Signal DNA and detection quality passport intelligence endpoints.
- FastAPI API, Typer CLI, Docker packaging, and CI quality gates.

### Safety

- Public source content remains untrusted.
- GitHub monitoring is metadata-only and never clones, downloads, imports,
  or executes repository code.
- Generated detections remain drafts until validation evidence supports
  promotion.

### Known limits at v0.9.0

- SQLite is the production-local backend; Postgres is planned for later
  multi-user deployment work.
- CLI coverage was narrower than API coverage for EPSS enrichment, GitHub
  metadata ingest, exports, and intelligence views.
- Live fetching is disabled by default and should be enabled only in
  controlled environments with appropriate host allowlists.

## v0.1.0

Initial defensive aggregator scaffolding (CVE / KEV / RSS / GitHub
metadata → ThreatRecord → draft detections). See git history for details.
