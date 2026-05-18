# GreyNOC Detector Engine

GreyNOC Detector Engine is a defensive threat-intelligence and detection-engine
platform for SOC operators, defenders, vulnerability analysts, and detection
engineers.

It ingests public CVE, CISA KEV, RSS/advisory/blog/news, and GitHub metadata;
normalizes source records; correlates weak signals; tracks AI-enabled attack
taxonomy terms; scores exploitability and early-warning signals; catalogs
threats in a local SQLite-backed library; records ingest run history; and
generates explainable draft detections for SOC validation.

## Safety Boundary

This is not an offensive tool. It does not generate exploit code, malware,
credential-theft logic, persistence techniques, unauthorized scanning,
weaponized payloads, bypass instructions, or abuse-enabling procedures.

GitHub monitoring is metadata-only. The engine can store repository names,
references, file/context metadata, timestamps, and defensive terms, but it does
not clone, download, install, import, or execute untrusted code.

## Current Capabilities

- Version `0.9.0` is the first near-production evaluation release for the
  defensive detection-engine foundation.
- Pydantic v2 schemas for CVEs, KEV entries, sources, source runs, indicators,
  threats, detections, validation evidence, score events, and score results.
- YAML source registry and scoring configuration under `config/`.
- Fixture-first CVE, KEV, RSS, and GitHub metadata ingestion.
- SQLite storage abstraction with tables for `raw_items`, `cves`,
  `kev_entries`, `threats`, `detections`, `source_runs`, and `score_events`.
- Threat-library create/update/list/get/deduplicate behavior with version
  changelogs.
- Correlation from CVEs to KEV, source references, exploit references, and AI
  attack terms.
- Explainable exploitability, risk, signal, and early-warning scoring with
  optional EPSS, exploit maturity, patch availability, internet exposure, and
  asset-exposure enrichment.
- EPSS enrichment workflow for updating stored CVEs from a fixture or the FIRST
  EPSS API when live fetching is intentionally enabled.
- Score-event history API for reviewing how threat scores changed over time.
- Draft Sigma, Splunk SPL, Elastic KQL, Microsoft Defender KQL, YARA
  metadata-only, and Suricata metadata-only detection generation.
- Filterable detection listing by status, detection kind, and related threat.
- Protected detection lifecycle workflow for moving detections from draft to
  validated or deprecated after SOC review, with structured validation evidence.
- FastAPI API and Typer CLI.

## Quickstart

```powershell
python -m pip install -e .[dev]
greynoc-detector init
greynoc-detector ingest cve --fixture data/fixtures/cve_sample.json
greynoc-detector ingest kev --fixture data/fixtures/kev_sample.json
greynoc-detector ingest rss --fixture data/fixtures/rss_sample.xml
greynoc-detector correlate
greynoc-detector score
greynoc-detector threats list
```

Show a correlated threat:

```powershell
greynoc-detector threats show thr-cve-cve-2026-12345
```

Generate draft detections after correlation:

```powershell
greynoc-detector detections generate thr-cve-cve-2026-12345
```

Run the API:

```powershell
greynoc-detector serve --host 127.0.0.1 --port 8000
```

## API Authentication

Mutating API endpoints are protected when `GREYNOC_API_KEY` is configured. Pass
the key as an `x-greynoc-api-key` header:

```powershell
curl -H "x-greynoc-api-key: $env:GREYNOC_API_KEY" \
  -X POST "http://127.0.0.1:8000/correlate"
```

If `GREYNOC_API_KEY` is unset, local development mode remains open.

## API Examples

```powershell
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8000/sources
curl http://127.0.0.1:8000/threats
curl http://127.0.0.1:8000/ingest/runs
curl "http://127.0.0.1:8000/detections?status=draft&kind=sigma"
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

## Local Fixture Workflow

Fixtures in `data/fixtures/` let developers test ingest, enrichment, and
correlation without live internet access:

- `cve_sample.json`
- `kev_sample.json`
- `rss_sample.xml`
- `github_sample.json`
- `epss_sample.json`

Live fetching is disabled by default. Set `GREYNOC_FETCH_LIVE=true` only when
you intentionally want configured HTTP sources to be queried. API fixture paths
are resolved under `GREYNOC_FIXTURE_ROOT` to prevent arbitrary filesystem reads.

## Source Run History and Score History

Each ingest job records a structured `SourceRun` with source ID, status,
message, item count, start/end timestamps, and error details for failed runs.
Recent runs are available from:

```powershell
curl http://127.0.0.1:8000/ingest/runs
```

Each scoring job records score events for later review:

```powershell
curl "http://127.0.0.1:8000/scores/events?target_id=thr-cve-cve-2026-12345"
```

## Configuration

Source policy and seed registries live in `config/sources.yaml`. Scoring
defaults live in `config/scoring.yaml`. Secrets and local paths should be
supplied by environment variables or `.env`, using `.env.example` as a template.

Important environment variables:

- `GREYNOC_DATABASE_PATH`
- `GREYNOC_DATA_DIR`
- `GREYNOC_FIXTURE_ROOT`
- `GREYNOC_SOURCES_PATH`
- `GREYNOC_SCORING_PATH`
- `GREYNOC_FETCH_LIVE`
- `GREYNOC_GITHUB_TOKEN`
- `GREYNOC_API_KEY`
- `GREYNOC_LOG_LEVEL`
- `GREYNOC_REQUEST_TIMEOUT_SECONDS`
- `GREYNOC_HTTP_RETRIES`
- `GREYNOC_MAX_RESPONSE_BYTES`
- `GREYNOC_ALLOWED_FETCH_HOSTS`

## Test Commands

```powershell
python -m pytest
ruff check .
ruff format --check .
mypy src
```

## Docker Usage

```powershell
docker compose up --build
```

The container exposes the FastAPI app on port `8000` and mounts local `data/`
and `config/`. The container runs as a non-root user and includes a `/health`
healthcheck.

## Current Limits

- The CLI currently exposes fixture ingest commands for CVE, KEV, and RSS.
  GitHub metadata ingest is available through the generic API/job path.
- Generated detections are drafts until validated with representative telemetry.
- SQLite is the first storage backend; Postgres remains a planned extension.
- Live source fetching must be enabled deliberately with `GREYNOC_FETCH_LIVE`.
- API-key auth is a starter protection layer; full user/RBAC support remains a
  planned extension.

## Roadmap

- Add a CLI command for GitHub metadata ingest and EPSS enrichment.
- Add Postgres storage behind the existing storage protocol.
- Add authenticated GitHub search adapter with rate-limit handling.
- Add asset inventory and affected-product popularity enrichment.
- Add validation evidence gates for promoting draft detections to validated
  status.
- Add SIEM/lake integrations for validating and tuning detections against real
  telemetry.
