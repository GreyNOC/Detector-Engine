# Changelog

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
