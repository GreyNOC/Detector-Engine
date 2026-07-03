# Changelog

## v1.0.2 - Post-quantum readiness + detection-quality harness

Released 2026-07-03.

Adds a post-quantum posture to the engine (both for its own artifacts and as a
threat dimension it detects) and a measurable detection-quality layer ported
from GreyNOC's GN-SLOP-DETECTION research engine. All additions are offline,
dependency-light, and preserve the defensive-only safety boundary.

### Post-quantum readiness — full PQC engine

The engine is now **post-quantum ready out of the box**: `gn doctor crypto`
reports PQ-ready with *no optional extras installed*, because public-key
non-repudiation is provided in pure stdlib.

Protecting the engine's own artifacts:

- **Always-on post-quantum signing (`crypto/hbs.py`).** A pure-stdlib LMS/HSS
  hash-based signature implementation (RFC 8554 / NIST SP 800-208), validated
  against the RFC 8554 Test Case 1 known-answer vector. This is real
  post-quantum non-repudiation with **no liboqs and no optional dependency**.
  Stateful one-time keys; reuse is prevented and persisted by the keystore.
- **Hybrid, crypto-agile signing (`crypto/signing.py`).** A detached,
  multi-algorithm envelope: HMAC-SHA256 (stdlib integrity) + LMS/HSS (stdlib PQ)
  + optional Ed25519 (`pq`) + optional FIPS-204 ML-DSA (`pq-mldsa`, liboqs).
- **Managed keystore (`crypto/keystore.py`).** `gn crypto keygen/keys/rotate/sign`
  — generation, rotation, retirement, and the safety-critical persistence of
  stateful LMS state *before* a signature is released (no leaf reuse across a
  crash or reload).
- **Hybrid KEM encryption (`crypto/kem.py`).** `gn crypto encrypt/decrypt` —
  ephemeral X25519 + ML-KEM-768 → HKDF → AES-256-GCM. Degrades to flagged
  classical-only when no ML-KEM backend is present.
- **Transparency log (`crypto/transparency.py`).** `gn crypto log` — an
  append-only RFC 6962-style Merkle log of published artifacts with
  post-quantum-signed checkpoints and inclusion proofs. Checkpoints are signed by
  a persistent, **pinnable** keystore key (a stable well-known public key, à la a
  Certificate-Transparency log), and `verify-checkpoint` **pins** that key so a
  checkpoint forged with any other key is rejected — authenticity, not just
  tamper-evidence. Pinning is exposed generally via
  `HybridSigner.verify(..., expected_public_keys=...)`: an asymmetric signature
  carries its own public key, so without a pin it proves only internal
  consistency; pinning the trusted key makes verification fail closed on a
  substituted signing key.
- **Self-test (`crypto/selftest.py`).** `gn crypto selftest` runs known-answer /
  round-trip tests for every available backend.
- **Algorithm registry (`crypto/algorithms.py`).** One authoritative source of
  algorithm facts — NIST category, byte sizes, governing standard, CNSA-2.0 /
  NIST IR 8547 deprecation dates — used everywhere. `gn crypto algorithms`.
- **Crypto-agile hashing.** `utils/hashing` is algorithm-selectable
  (SHA-256/SHA-3/BLAKE2), refuses MD5/SHA-1, and exposes quantum-resistance.

Detecting threats to *other* systems' cryptography:

- **Quantum-risk classifier** (`analysis/quantum_risk.py`, `gn quantum scan`) —
  flags quantum-vulnerable crypto and harvest-now-decrypt-later risk, attaching
  an explainable `QuantumRiskAssessment` to threats, with an offline eval
  harness (`eval/quantum`, `gn quantum eval`).
- **Crypto inventory + Mosca** (`analysis/crypto_inventory.py`,
  `analysis/mosca.py`, `gn quantum inventory` / `mosca`) — posture summary per
  asset and Mosca's-inequality harvest-now-decrypt-later analysis.
- **CBOM** (`analysis/cbom.py`, `gn crypto cbom`) — CycloneDX 1.6 Cryptographic
  Bill of Materials emit/parse/assess.
- **TLS / X.509 posture** (`analysis/tls_posture.py`, `gn quantum cert`) —
  offline certificate quantum-exposure classification; optional active probe is
  off by default and SSRF-guarded.
- **Migration planner** (`analysis/pqc_migration.py`, `gn quantum plan` /
  `timeline`) — prioritized CNSA-2.0 / NIST IR 8547 migration plan.

Surface:

- **CLI:** new `gn crypto` app and an expanded `gn quantum` app.
- **API:** new read-only `/crypto/*` and `/quantum/*` routes.
- **Extras:** `pq` (Ed25519/X25519), `pq-mldsa` (liboqs ML-DSA/ML-KEM),
  `pq-pure` (pure-Python ML-KEM/ML-DSA, no C toolchain).
- See `docs/post_quantum_readiness.md` and `docs/standards_reference.md`.

### Detection quality

- **Offline forecast-evaluation harness** (`greynoc_detector_engine.eval`,
  `gn eval`). Scores `AttackForecast` probabilities against realized outcomes
  with the metrics the literature uses — ROC-AUC, TPR at a fixed low FPR, F1,
  ECE/Brier — plus Platt calibration and glass-box learned `predictive_fusion_weights`.
  Pure-Python, never on the request path. See `docs/detection_quality.md`.
- **Adversarial-evasion resistance.** OSINT ingest now strips zero-width / bidi
  controls and folds homoglyphs before entity extraction, so a CVE id, product,
  or actor name hidden behind lookalike characters still matches; the evasion is
  also surfaced as a finding.

### Quality

- New unit/integration tests across the PQC layer — LMS/HSS (incl. the RFC 8554
  KAT), hybrid KEM, keystore (incl. no-leaf-reuse-across-reload), transparency
  log, crypto self-test, crypto inventory, CBOM, migration planner, TLS posture,
  the quantum eval harness, and end-to-end CLI + API integration tests — plus the
  pre-existing eval harness, evasion normalization, hybrid signing, hashing
  agility, and quantum-risk classifier tests. Verification at release: 361
  tests pass, 2 tests skip optional backends, ruff passes, ruff format passes,
  and strict mypy passes.

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
