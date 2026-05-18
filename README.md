# GreyNOC Detector Engine

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

See `docs/predictive_engine.md`, `docs/osint_layer.md`, and
`docs/local_network_sensor.md` for the predictive overlay; `docs/security_review.md`
for the engine's own hardening; and `CHANGELOG.md` for release notes.

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

## Quickstart

The preferred shorthand is `gn - <command>`. The `GN - <command>` alias and the
original `greynoc-detector <command>` entrypoint are also supported.

```powershell
python -m pip install -e .[dev]
gn - init

# Authoritative + research feeds
gn - ingest cve --fixture data/fixtures/cve_sample.json
gn - ingest kev --fixture data/fixtures/kev_sample.json
gn - ingest rss --fixture data/fixtures/rss_sample.xml

# Predictive priors and OSINT IOC feeds
gn - ingest epss        --fixture data/fixtures/epss_sample.json
gn - ingest threatfox   --fixture data/fixtures/threatfox_sample.json
gn - ingest urlhaus     --fixture data/fixtures/urlhaus_sample.json
gn - ingest ransomwatch --fixture data/fixtures/ransomwatch_sample.json

# Correlate + predict (forecasts are computed inline)
gn - correlate
gn - predict run --asset-inventory config/asset_inventory.yaml
gn - predict run --force
gn - threats list
gn - predict campaigns
```

Show a correlated threat:

```powershell
gn - threats show thr-cve-cve-2026-12345
```

Generate draft detections after correlation:

```powershell
gn - detections generate thr-cve-cve-2026-12345
```

Run the API:

```powershell
gn - serve --host 127.0.0.1 --port 8000
```

Run the loopback-bound darknet listener:

```powershell
gn - sensor honeypot --port 31337
```

To intentionally expose the honeypot outside loopback, set both a non-loopback
bind address and the explicit safety opt-in:

```powershell
gn - sensor honeypot --bind 0.0.0.0 --port 31337 --allow-external-bind
```

## API Authentication

Mutating API endpoints are open only for local convenience when `GREYNOC_ENV`
is `local`, `dev`, or `test` and no API key is configured. Outside those
environments, production fails closed: `GREYNOC_API_KEY` must be set and
mutating routes require the key in an `x-greynoc-api-key` header.

```powershell
curl -H "x-greynoc-api-key: $env:GREYNOC_API_KEY" \
  -X POST "http://127.0.0.1:8000/correlate"
```

Missing or invalid keys return `401 Unauthorized` outside local/dev/test.
Expensive duplicate jobs return `409 Conflict` while the same job is already
running. Collection/list endpoints accept `limit`, default to `100`, and cap at
`500`.

## API Examples

```powershell
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8000/sources
curl http://127.0.0.1:8000/threats
curl http://127.0.0.1:8000/ingest/runs
curl "http://127.0.0.1:8000/detections?status=draft&kind=sigma&limit=100"
curl "http://127.0.0.1:8000/exports/detections?status=validated&export_format=json"
curl "http://127.0.0.1:8000/intelligence/threats/thr-cve-cve-2026-12345/signal-dna"
curl "http://127.0.0.1:8000/scores/events?target_id=thr-cve-cve-2026-12345&score_type=risk"
curl -H "x-greynoc-api-key: $env:GREYNOC_API_KEY" -X POST "http://127.0.0.1:8000/ingest/cve?fixture=cve_sample.json"
curl -H "x-greynoc-api-key: $env:GREYNOC_API_KEY" -X POST "http://127.0.0.1:8000/ingest/kev?fixture=kev_sample.json"
curl -H "x-greynoc-api-key: $env:GREYNOC_API_KEY" -X POST "http://127.0.0.1:8000/ingest/rss?fixture=rss_sample.xml"
curl -H "x-greynoc-api-key: $env:GREYNOC_API_KEY" -X POST "http://127.0.0.1:8000/enrich/epss?fixture=epss_sample.json"
curl -H "x-greynoc-api-key: $env:GREYNOC_API_KEY" -X POST "http://127.0.0.1:8000/correlate"
```

The generic ingest endpoint also supports source types that do not yet have a
dedicated CLI command:

```powershell
curl -H "x-greynoc-api-key: $env:GREYNOC_API_KEY" \
  -X POST "http://127.0.0.1:8000/ingest/run?source=github&fixture=github_sample.json"
```

Promote a reviewed detection to validated status with evidence:

```powershell
curl -H "x-greynoc-api-key: $env:GREYNOC_API_KEY" \
  -H "Content-Type: application/json" \
  -X PATCH "http://127.0.0.1:8000/detections/det-example/status" \
  -d '{"status":"validated","note":"Validated against representative telemetry.","evidence":{"result":"passed","summary":"No false positives in sample window.","telemetry_source":"splunk-lab","sample_size":100,"true_positive_count":3,"false_positive_count":0,"reviewer":"grey-soc"}}'
```

Submit analyst feedback to re-tune predictive fusion weights:

```powershell
curl -H "x-greynoc-api-key: $env:GREYNOC_API_KEY" \
  -H "Content-Type: application/json" \
  -X POST "http://127.0.0.1:8000/feedback" \
  -d '{"threat_id":"thr-cve-cve-2026-12345","verdict":"true_positive","analyst":"grey-soc"}'
```

Run a what-if counterfactual:

```powershell
curl -H "x-greynoc-api-key: $env:GREYNOC_API_KEY" \
  -H "Content-Type: application/json" \
  -X POST "http://127.0.0.1:8000/predict/counterfactual/thr-cve-cve-2026-12345" \
  -d '{"interventions":["patch_applied","ioc_blocked"]}'
```

Export to STIX 2.1 or to a MITRE ATT&CK Navigator layer:

```powershell
curl http://127.0.0.1:8000/export/stix > bundle.json
curl http://127.0.0.1:8000/export/attack-navigator > layer.json
```

## API Routes

- `GET /health`
- `GET /sources`
- `GET /threats`
- `GET /threats/{threat_id}`
- `GET /cves`
- `GET /cves/{cve_id}`
- `GET /kev`
- `GET /detections`
- `GET /detections/{detection_id}`
- `GET /exports/detections`
- `GET /intelligence/threats/{threat_id}/signal-dna`
- `GET /intelligence/detections/{detection_id}/quality-passport`
- `GET /scores/events`
- `GET /ingest/runs`
- `POST /ingest/cve`
- `POST /ingest/kev`
- `POST /ingest/rss`
- `POST /ingest/run`
- `POST /enrich/epss`
- `POST /correlate`
- `POST /correlate/run`
- `POST /detections/generate/{threat_id}`
- `POST /detections/{detection_id}/test`
- `PATCH /detections/{detection_id}/status`
- `POST /predict/run`
- `GET  /predict/forecasts/{threat_id}`
- `GET  /predict/threat/{threat_id}`
- `GET  /predict/imminent`
- `GET  /predict/accuracy`
- `POST /predict/counterfactual/{threat_id}`
- `GET  /campaigns`
- `GET  /campaigns/{campaign_id}`
- `POST /network/discover`
- `GET  /network/devices`
- `GET  /network/ics-observations`
- `POST /sensor/run`
- `GET  /sensor/signals`
- `GET  /sensor/honeypot/events`
- `POST /feedback`
- `GET  /feedback`
- `GET  /export/stix`
- `GET  /export/attack-navigator`

## Local Fixture Workflow

Fixtures in `data/fixtures/` let developers test ingest, enrichment, and
correlation without live internet access:

- `cve_sample.json`
- `kev_sample.json`
- `rss_sample.xml`
- `github_sample.json`
- `epss_sample.json`
- `threatfox_sample.json`
- `urlhaus_sample.json`
- `ransomwatch_sample.json`
- `sample_rules_repo/`

Live fetching is disabled by default. Set `GREYNOC_FETCH_LIVE=true` only when
you intentionally want configured HTTP sources to be queried. API ingest
fixture paths are resolved under `GREYNOC_FIXTURE_ROOT` (default:
`data/fixtures`) to prevent arbitrary filesystem reads. Prediction asset
inventory paths accept the configured fixture/data roots and the optional
`GREYNOC_FIXTURE_DIR` compatibility root.

## Source Run History and Score History

Each ingest job records a structured `SourceRun` with source ID, status,
message, item count, start/end timestamps, and error details for failed runs.
Recent runs are available from:

```powershell
curl "http://127.0.0.1:8000/ingest/runs?limit=100"
```

Each scoring job records score events for later review:

```powershell
curl "http://127.0.0.1:8000/scores/events?target_id=thr-cve-cve-2026-12345&limit=100"
```

## Engine Self-Check (Doctor)

```powershell
gn - doctor          # safety defaults (honeypot bind, HTTP caps)
gn - doctor sources  # per-source ingest health
```

## Configuration

Source policy and seed registries live in `config/sources.yaml`. Scoring
defaults live in `config/scoring.yaml`. Predictive horizon model parameters
live in `config/attack_horizon.yaml`. An asset inventory example lives in
`config/asset_inventory.example.yaml`. Secrets and local paths should be
supplied by environment variables or `.env`, using `.env.example` as a
template.

Important environment variables:

- `GREYNOC_ENV`
- `GREYNOC_DATABASE_PATH`
- `GREYNOC_DATA_DIR`
- `GREYNOC_FIXTURE_ROOT`
- `GREYNOC_FIXTURE_DIR`
- `GREYNOC_SOURCES_PATH`
- `GREYNOC_SCORING_PATH`
- `GREYNOC_FETCH_LIVE`
- `GREYNOC_GITHUB_TOKEN`
- `GREYNOC_API_KEY`
- `GREYNOC_LOG_LEVEL`
- `GREYNOC_REQUEST_TIMEOUT_SECONDS`
- `GREYNOC_HTTP_RETRIES`
- `GREYNOC_MAX_RESPONSE_BYTES` (default `5000000`)
- `GREYNOC_ALLOWED_FETCH_HOSTS`
- `GREYNOC_USER_AGENT`

## Test Commands

```powershell
python -m pip install -e .[dev]
ruff check .
ruff format --check .
mypy src
pytest --cov=greynoc_detector_engine --cov-report=term-missing
```

## Docker Usage

```powershell
$env:GREYNOC_API_KEY = "replace-with-a-long-random-key"
docker compose up --build
```

Docker Compose runs with `GREYNOC_ENV=production`, requires
`GREYNOC_API_KEY`, and publishes the FastAPI app on `127.0.0.1:8000` by
default. The container still listens on port `8000` internally, mounts local
`data/` and `config/`, runs as a non-root user, and includes a `/health`
healthcheck.

## Current Limits

- Generated detections are drafts until validated with representative
  telemetry.
- SQLite is the first storage backend; Postgres remains a planned extension.
- Live source fetching must be enabled deliberately with `GREYNOC_FETCH_LIVE`.
- API-key auth is a starter protection layer; full user/RBAC support remains a
  planned extension.
- The predictive horizon model is parametric and hand-tuned; the same feature
  contract supports swapping in a learned model later.
- Prediction runs record `ForecastRun` performance metrics and skip unchanged
  threats by input fingerprint; use `gn - predict run --force` for a full
  recompute.

## Roadmap

- Add Postgres storage behind the existing storage protocol.
- Add authenticated GitHub search adapter with rate-limit handling.
- Add validation evidence gates for promoting draft detections to validated
  status (initial version shipped; expand evidence schema and reviewers).
- Add SIEM/lake integrations for validating and tuning detections against
  real telemetry.
- Surface counterfactual + accuracy dashboards in a small web UI.
