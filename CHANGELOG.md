# Changelog

## v0.9.0 - 2026-05-18

GreyNOC Detector Engine v0.9.0 is the first release candidate for a serious
defensive threat-intelligence and detection-engine foundation.

### Added

- Fixture-first CVE, CISA KEV, RSS, and GitHub metadata ingestion.
- SQLite-backed storage for raw items, CVEs, KEV entries, threats, detections,
  source runs, and score events.
- Explainable exploitability, risk, early-warning, AI-abuse, and signal scoring.
- EPSS enrichment using local fixtures or the FIRST EPSS API when live fetching
  is deliberately enabled.
- Detection generation for Sigma, Splunk SPL, Elastic KQL, Microsoft Defender
  KQL, YARA metadata-only, and Suricata metadata-only outputs.
- Evidence-gated detection lifecycle workflow for validated and deprecated
  detection states.
- Detection export bundles for validated detection handoff.
- Detection test harness for positive and negative fixture checks.
- Score-event history API.
- Signal DNA and detection quality passport intelligence endpoints.
- FastAPI API, Typer CLI, Docker packaging, and CI quality gates.

### Safety

- Public source content remains untrusted.
- GitHub monitoring is metadata-only and never clones, downloads, imports, or
  executes repository code.
- Generated detections remain drafts until validation evidence supports
  promotion.

### Known Limits

- SQLite is the production-local backend; Postgres is planned for later
  multi-user deployment work.
- CLI coverage is still narrower than API coverage for EPSS enrichment, GitHub
  metadata ingest, exports, and intelligence views.
- Live fetching is disabled by default and should be enabled only in controlled
  environments with appropriate host allowlists.
