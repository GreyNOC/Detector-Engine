# GreyNOC Detector Engine v0.9 Release Plan

## Release Goal

Release v0.9.0 as the first near-production defensive detection-engine
candidate. The release should be credible for SOC engineering evaluation:
local-first, fixture-testable, safety-bounded, explainable, and ready for
iterative validation work.

## Scope

- CVE, CISA KEV, RSS, and GitHub metadata ingestion foundations.
- Local SQLite storage with source-run and score-event history.
- Threat-library cataloging with deduplication, versioning, and provenance.
- Explainable scoring across exploitability, early warning, risk, AI abuse, and
  signal strength.
- EPSS enrichment with fixture and live-fetch paths.
- Draft detection generation across Sigma, Splunk, Elastic, Defender, YARA
  metadata, and Suricata metadata.
- Evidence-gated detection validation lifecycle.
- Detection export bundles for validated detections.
- Detection test harness for positive and negative fixture checks.
- Signal DNA and detection quality passport intelligence views.
- API, CLI, Docker, and documentation suitable for local evaluator use.

## Release Gates

- `ruff check .`
- `ruff format --check .`
- `mypy src`
- `pytest --cov=greynoc_detector_engine --cov-report=term-missing`
- Package build with `python -m build` when the local build module is available.
- No secrets committed.
- No exploit code, malware logic, credential theft, persistence behavior,
  unauthorized scanning, or offensive automation.
- GitHub metadata handling remains metadata-only.

## Release Artifacts

- Python package metadata version: `0.9.0`
- Runtime `__version__`: `0.9.0`
- FastAPI OpenAPI version: `0.9.0`
- Git tag: `v0.9.0`
- Release notes: `CHANGELOG.md`

## Known Limitations

- SQLite is the only implemented storage backend.
- Authentication is API-key based and intended as a starter control, not full
  enterprise RBAC.
- Generated detections are defensive drafts until validation evidence and test
  fixtures support promotion.
- Some newer API workflows do not yet have equivalent CLI commands.
- Live source fetching must be explicitly enabled and should use host
  allowlists.

## Post-v0.9 Priorities

1. Add Postgres storage and migrations.
2. Add CLI parity for EPSS enrichment, exports, GitHub metadata ingest, and
   intelligence reports.
3. Add configurable scoring weights from `config/scoring.yaml`.
4. Persist correlation relationships as a queryable evidence graph.
5. Add RBAC-ready authentication and structured audit logging.
6. Build CI release automation for signed artifacts and GitHub Releases.
