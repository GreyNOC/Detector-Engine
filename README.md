# GreyNOC Detector Engine

[![CI](https://github.com/GreyNOC/Detector-Engine/actions/workflows/ci.yml/badge.svg)](https://github.com/GreyNOC/Detector-Engine/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/GreyNOC/Detector-Engine?display_name=tag)](https://github.com/GreyNOC/Detector-Engine/releases/tag/v1.0.2)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Security Policy](https://img.shields.io/badge/security-policy-blue)](SECURITY.md)

> **Public demo / research engine:** This repository is intentionally public
> to share GreyNOC's defensive security research, detection-engine concepts,
> and community-facing project direction. It is not a production SOC
> deployment, does not include customer environments, and should not contain
> secrets, private telemetry, internal infrastructure details, or proprietary
> client-specific logic.

GreyNOC Detector Engine is a defensive, OSINT-driven threat-intelligence and
detection-engine framework for SOC operators, defenders, vulnerability
analysts, and detection engineers.

It ingests public CVE, CISA KEV, vendor PSIRT, RSS/advisory/blog, news, GitHub
metadata, FIRST.org EPSS exploit-prediction scores, abuse.ch ThreatFox and
URLhaus IOC feeds, and public ransomware leak-site metadata. The engine
normalizes records, correlates weak signals, classifies AI-enabled attack
taxonomy terms, clusters threats into campaigns, records ingest history, and
produces an explainable `AttackForecast` per threat: probability, horizon,
p50/p90 days, confidence, and named drivers. Threats are catalogued in a local
SQLite-backed library, and draft detections are generated for SOC validation
under an evidence-gated lifecycle.

## Quick Start

```bash
python -m pip install -e '.[dev]'
gn workflow demo --pretty
```

The golden-path demo is offline by default. It initializes local paths, ingests
bundled fixture-backed sources, correlates signals, runs the predictive layer,
drafts detections, and prints a compact JSON report.

Useful follow-up commands:

```bash
gn status --pretty
gn doctor
gn doctor crypto
gn jobs list --pretty
gn threats list --query edgegateway --min-probability 0.5 --summary --pretty
gn detections list --pretty
gn eval report --pretty
gn quantum scan "OpenSSL TLS RSA key exchange flaw; harvest now decrypt later" --pretty
```

## Safety Boundary

This is not an offensive tool. It does not generate exploit code, malware,
credential-theft logic, persistence techniques, unauthorized scanning,
weaponized payloads, bypass instructions, or abuse-enabling procedures.

Repository-content boundaries:

- `github_search` sources store API metadata only. They never clone, install,
  import, or execute repository code.
- `git_repository` sources can shallow-clone allowlisted defensive-content
  repositories for rule harvesting. Cloning is opt-in per source, HTTPS-only,
  shallow, sandboxed, hooks-disabled, and content-only.
- Git clone allowlists are path-boundary aware. An allowlist entry such as
  `github.com/sigmahq/sigma` does not match `github.com/sigmahq/sigma-evil`
  or paths containing `.` or `..` segments.
- Text files must match the per-source extension allowlist before ingestion.
  Nothing from cloned repositories is executed.

See [docs/osint_layer.md](docs/osint_layer.md) for the full OSINT and git
repository policy.

## Security Defaults

- Live fetching is disabled by default with `GREYNOC_FETCH_LIVE=false`.
- Live HTTP fetches are HTTPS-only by default. Plain HTTP requires
  `GREYNOC_ALLOW_INSECURE_HTTP=true`.
- Live fetches reject loopback, private, link-local, multicast, reserved, and
  unspecified IP literal hosts by default. Internal lab feeds require an
  explicit `GREYNOC_BLOCK_PRIVATE_FETCH_HOSTS=false` decision.
- `GREYNOC_ALLOWED_FETCH_HOSTS` can restrict live fetches to a deployment
  allowlist.
- HTTP responses and fixture reads are bounded by
  `GREYNOC_MAX_RESPONSE_BYTES` (default: `5000000`).
- Redirects are manually revalidated and capped. Cross-host redirects are
  refused unless the destination is explicitly allowlisted.
- API-key authentication is a starter protection layer. Production-style use
  should sit behind a reverse proxy or API gateway with TLS, logging, network
  policy, rate limiting, and user/RBAC controls.
- Detection and STIX-export artifacts can be signed with a crypto-agile, hybrid
  quantum-safe signature (`gn export stix --sign`). See
  [Post-Quantum Readiness](docs/post_quantum_readiness.md).

Run the local safety self-check at any time:

```bash
gn doctor
```

## Current Capabilities

- Pydantic v2 schemas for CVEs, KEV entries, sources, source runs,
  indicators, threats, detections, validation evidence, score events, score
  results, predictive forecasts, campaigns, ICS observations, network devices,
  intrusion signals, and honeypot events.
- YAML source registry and scoring configuration under `config/`.
- Fixture-first CVE, KEV, RSS, GitHub, EPSS, ThreatFox, URLhaus, Ransomwatch,
  and `git_repository` ingestion.
- SQLite storage abstraction with WAL mode, indexes, and versioned migrations.
- Threat-library create/update/list/get/deduplicate with version changelogs.
- Correlation across CVEs, KEV, source mentions, AI-attack terms, and
  campaigns.
- Explainable scoring for exploitability, risk, signal, early-warning,
  AI-abuse, and predictive attack forecasting.
- EPSS enrichment from a fixture or the FIRST EPSS API when live fetching is
  intentionally enabled.
- Draft Sigma, Splunk SPL, Elastic KQL, Microsoft Defender KQL, YARA
  metadata-only, and Suricata metadata-only detection generation, with
  attacker-influenced inputs sanitized by `detection/safety.py`.
- Protected detection lifecycle workflow for moving detections from draft to
  validated or deprecated after SOC review.
- Spacestation passive sensor and an opt-in loopback-bound darknet TCP
  listener.
- Analyst feedback loop, forecast accuracy tracker, counterfactual what-if
  engine, STIX 2.1 exporter, and ATT&CK Navigator exporter.
- Offline forecast-evaluation harness (`gn eval`) reporting ROC-AUC, TPR at a
  fixed low FPR, F1, and calibration error (ECE/Brier), with Platt calibration
  and glass-box learned `predictive_fusion_weights`.
- Adversarial-evasion resistance: OSINT ingest strips zero-width/bidi controls
  and folds homoglyphs before entity extraction so disguised CVEs, products, and
  actor names still match, and flags the obfuscation as a finding.
- **Post-quantum cryptography engine** — *PQ-ready out of the box, no optional
  extras required*:
  - Always-on post-quantum signing via a pure-stdlib LMS/HSS implementation
    (RFC 8554 / NIST SP 800-208, validated against the RFC's known-answer
    vector), in a crypto-agile hybrid envelope alongside HMAC and optional
    Ed25519 / FIPS-204 ML-DSA. A managed keystore (`gn crypto keygen/sign/rotate`)
    safely persists stateful one-time-key state; hybrid X25519+ML-KEM artifact
    encryption (`gn crypto encrypt`); and a Merkle, PQ-signed transparency log
    (`gn crypto log`). `gn doctor crypto` / `gn crypto selftest` report posture.
  - A PQC threat dimension over *other* systems' crypto: a harvest-now-decrypt-
    later classifier (`gn quantum scan`), crypto-inventory + Mosca analysis
    (`gn quantum inventory` / `mosca`), CycloneDX CBOM (`gn crypto cbom`), X.509
    posture (`gn quantum cert`), and a CNSA-2.0 / NIST IR 8547 migration planner
    (`gn quantum plan` / `timeline`). See `docs/post_quantum_readiness.md`.
- FastAPI API and Typer CLI.

## Current Limits

- This is not a SaaS or multi-tenant SOC platform.
- SQLite is the default local backend; Postgres is future work.
- Generated detections remain drafts until validated with structured human
  evidence.
- Live fetching should only be enabled in controlled environments with source
  allowlists and network egress controls.
- API rate limiting is intentionally left to the reverse proxy or API gateway.

## Configuration

Copy `.env.example` to `.env` for local overrides. Important settings:

```bash
GREYNOC_ENV=local
GREYNOC_DATABASE_PATH=data/threat_library/greynoc_detector_engine.sqlite
GREYNOC_FIXTURE_ROOT=data/fixtures
GREYNOC_FETCH_LIVE=false
GREYNOC_API_KEY=
GREYNOC_MAX_RESPONSE_BYTES=5000000
GREYNOC_ALLOW_INSECURE_HTTP=false
GREYNOC_BLOCK_PRIVATE_FETCH_HOSTS=true
GREYNOC_ALLOWED_FETCH_HOSTS='["www.cisa.gov","services.nvd.nist.gov","api.github.com","api.first.org"]'
```

## API And CLI

Start the API locally:

```bash
greynoc-detector serve --host 127.0.0.1 --port 8000
```

Run fixture-backed ingest manually:

```bash
greynoc-detector ingest cve --fixture data/fixtures/cve_sample.json
greynoc-detector ingest kev --fixture data/fixtures/kev_sample.json
greynoc-detector ingest rss --fixture data/fixtures/rss_sample.xml
greynoc-detector predict run
greynoc-detector threats list --summary --pretty
greynoc-detector threats list --cve CVE-2026-12345 --summary --pretty
greynoc-detector detections generate <threat-id>
```

Threat review supports search and triage filters across title, summary, CVEs,
products, actors, sectors, campaigns, forecast horizon, AI attack type, and
probability windows. The API exposes the same view with `GET /threats` query
parameters and a compact `GET /threats/search` endpoint.

Inspect the main workflow docs:

- [docs/cli_operator_guide.md](docs/cli_operator_guide.md)
- [docs/predictive_engine.md](docs/predictive_engine.md)
- [docs/osint_layer.md](docs/osint_layer.md)
- [docs/local_network_sensor.md](docs/local_network_sensor.md)
- [docs/security_review.md](docs/security_review.md)
- [docs/post_quantum_readiness.md](docs/post_quantum_readiness.md)
- [docs/detection_quality.md](docs/detection_quality.md)

## Development

```bash
python -m pip install -e '.[dev]'
pytest
ruff check src tests
mypy
```

For release history, see [CHANGELOG.md](CHANGELOG.md) and
[docs/release_notes_v1.0.2.md](docs/release_notes_v1.0.2.md).
