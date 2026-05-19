# GreyNOC Detector Engine

[![CI](https://github.com/GreyNOC/Detector-Engine/actions/workflows/ci.yml/badge.svg)](https://github.com/GreyNOC/Detector-Engine/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/GreyNOC/Detector-Engine?display_name=tag)](https://github.com/GreyNOC/Detector-Engine/releases/tag/v1.0.0)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Security Policy](https://img.shields.io/badge/security-policy-blue)](SECURITY.md)

> **Public demo / research engine:** This repository is intentionally public to share GreyNOC's defensive security research, detection-engine concepts, and community-facing project direction. It is not a production SOC deployment, does not include customer environments, and should not contain secrets, private telemetry, internal infrastructure details, or proprietary client-specific logic.

GreyNOC Detector Engine is a defensive, OSINT-driven, *predictive* threat
intelligence and detection-engine platform for SOC operators, defenders,
vulnerability analysts, and detection engineers.

It ingests public CVE, CISA KEV, vendor PSIRT, RSS/advisory/blog, news, GitHub
metadata, **FIRST.org EPSS exploit-prediction scores**, **abuse.ch ThreatFox
and URLhaus IOC feeds**, and **public ransomware leak-site metadata**;
normalizes source records; correlates weak signals; classifies AI-enabled
attack taxonomy terms; clusters threats into campaigns; attributes signals to
known public threat actors; records ingest run history; and produces a
forward-looking, fully explainable `AttackForecast` per threat — probability,
horizon, p50/p90 days, confidence, and a list of named drivers. Threats are
catalogued in a local SQLite-backed library and draft detections (Sigma,
Splunk SPL, Elastic KQL, Microsoft Defender KQL, YARA, Suricata) are generated
for SOC validation under an evidence-gated lifecycle.

## v1.0.0 Release

Version 1.0.0 is the first advanced, operator-grade release of the Detector
Engine. It is ready for public demo use, local lab evaluation, and controlled
SOC pilot review.

```bash
python -m pip install -e '.[dev]'
gn workflow demo --pretty
```

The golden-path demo is offline by default. It initializes local paths, ingests
bundled fixture-backed sources, correlates signals, runs the predictive layer,
drafts detections, and prints a compact JSON report.

For the complete release copy, see
[`docs/release_notes_v1.0.0.md`](docs/release_notes_v1.0.0.md). For the
historical changelog, see [`CHANGELOG.md`](CHANGELOG.md).

## Who This Is For

- SOC analysts who need a repeatable defensive triage queue.
- Detection engineers who want draft Sigma, SPL, KQL, YARA metadata, and
  Suricata metadata for review.
- Threat-intelligence analysts who want OSINT enrichment, weak-signal
  correlation, and explainable forecast drivers.
- Defensive security labs evaluating local-first detection-engine workflows.

## Current Limits

- This is not a SaaS or multi-tenant SOC platform.
- SQLite is the default local backend; Postgres is planned as future work.
- API-key authentication is a starter protection layer; production-style use
  should sit behind a reverse proxy or API gateway with TLS, logging, network
  policy, and user/RBAC controls.
- Generated detections remain drafts until validated with structured human
  evidence.
- Live fetching is disabled by default and should only be enabled in controlled
  environments with appropriate source allowlists.

See `docs/predictive_engine.md`, `docs/osint_layer.md`,
`docs/local_network_sensor.md`, and `docs/cli_operator_guide.md` for the main
workflows; `docs/advanced_tool_roadmap.md` for the advanced-tool boundary;
`docs/security_review.md` for the engine's own hardening; and
`CHANGELOG.md` for release notes.

## Safety Boundary

This is not an offensive tool. It does not generate exploit code, malware,
credential-theft logic, persistence techniques, unauthorized scanning,
weaponized payloads, bypass instructions, or abuse-enabling procedures.

### Trust boundary for repository content

- `github_search` sources store API metadata only — never clone, install,
  import, or execute repository code.
- `git_repository` sources can shallow-clone **allowlisted** defensive-content
  repos (e.g. SigmaHQ/sigma, YARA-Rules/rules, Neo23x0/signature-base) for
  rule harvesting. Cloning is **opt-in per source**, HTTPS-only, shallow,
  sandboxed, hooks-disabled, and **content-only** — text files matching a
  per-source extension allowlist are read; nothing is ever executed and the
  clone is deleted after ingestion. See `docs/osint_layer.md` for the full
  policy block.

## Current Capabilities

- Pydantic v2 schemas for CVEs, KEV entries, sources, source runs, indicators,
  threats, detections, validation evidence, score events, score results,
  predictive forecasts, campaigns, ICS observations, network devices,
  intrusion signals, and honeypot events.
- YAML source registry and scoring configuration under `config/`.
- Fixture-first CVE, KEV, RSS, GitHub, EPSS, ThreatFox, URLhaus, Ransomwatch,
  and `git_repository` ingestion.
- SQLite storage abstraction (WAL mode + indexed, with versioned migrations)
  for raw items, CVEs, KEV entries, threats, detections, source runs, score
  events, EPSS scores, campaigns, attack forecasts, indicator reputation,
  assets, target likelihoods, network devices, ICS observations, intrusion
  signals, honeypot events, threat feedback, scan baselines, source health,
  and forecast outcomes.
- Threat-library create/update/list/get/deduplicate with version changelogs.
- Correlation: CVE ↔ KEV ↔ source mentions ↔ AI-attack terms ↔ campaigns.
- Explainable scoring: exploitability, risk, signal, early-warning, AI-abuse,
  and predictive `AttackForecast` (probability + horizon + drivers).
- EPSS enrichment workflow for updating stored CVEs from a fixture or the
  FIRST EPSS API when live fetching is intentionally enabled.
- Score-event history API for reviewing how threat scores changed over time.
- Draft Sigma, Splunk SPL, Elastic KQL, Microsoft Defender KQL, YARA
  metadata-only, and Suricata metadata-only detection generation, with
  attacker-influenced inputs sanitized via `detection/safety.py`.
- Filterable detection listing by status, detection kind, and related threat.
- Protected detection lifecycle workflow for moving detections from draft to
  validated or deprecated after SOC review, with structured validation
  evidence.
- ICS classifier (Modbus, S7, DNP3, EtherNet/IP, BACnet, OPC UA, IEC
  60870-5-104, Profinet, FINS, MELSEC, CODESYS) — detection only.
- Spacestation passive sensor (port-scan / slow-scan / SYN-flood / port-knock
  / ICS-probe / darknet-touch detectors with adaptive per-host EWMA baselines)
  and an opt-in loopback-bound darknet TCP listener.
- Analyst feedback loop, forecast accuracy tracker (Brier + calibration),
  counterfactual what-if engine, STIX 2.1 + ATT&CK Navigator exporters.
- `doctor` CLI for safety self-check and per-source ingest health.
- FastAPI API and Typer CLI.
