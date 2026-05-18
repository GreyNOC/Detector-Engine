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

- Pydantic v2 schemas for CVEs, KEV entries, sources, source runs, indicators,
  threats, detections, and score results.
- YAML source registry and scoring configuration under `config/`.
- Fixture-first CVE, KEV, RSS, and GitHub metadata ingestion.
- SQLite storage abstraction with tables for `raw_items`, `cves`,
  `kev_entries`, `threats`, `detections`, `source_runs`, and `score_events`.
- Threat-library create/update/list/get/deduplicate behavior with version
  changelogs.
- Basic correlation from CVEs to KEV, source references, exploit references,
  and AI attack terms.
- Explainable exploitability, risk, signal, and early-warning scoring.
- Draft Sigma, Splunk SPL, Elastic KQL, Microsoft Defender KQL, YARA
  metadata-only, and Suricata metadata-only detection generation.
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

## API Examples

```powershell
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8000/sources
curl http://127.0.0.1:8000/threats
curl http://127.0.0.1:8000/ingest/runs
curl -X POST "http://127.0.0.1:8000/ingest/cve?fixture=data/fixtures/cve_sample.json"
curl -X POST "http://127.0.0.1:8000/ingest/kev?fixture=data/fixtures/kev_sample.json"
curl -X POST "http://127.0.0.1:8000/ingest/rss?fixture=data/fixtures/rss_sample.xml"
curl -X POST "http://127.0.0.1:8000/correlate"
```

The generic ingest endpoint also supports source types that do not yet have a
dedicated CLI command:

```powershell
curl -X POST "http://127.0.0.1:8000/ingest/run?source=github&fixture=data/fixtures/github_sample.json"
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
- `GET /ingest/runs`
- `POST /ingest/cve`
- `POST /ingest/kev`
- `POST /ingest/rss`
- `POST /ingest/run`
- `POST /correlate`
- `POST /correlate/run`
- `POST /detections/generate/{threat_id}`

## Local Fixture Workflow

Fixtures in `data/fixtures/` let developers test ingest and correlation without
live internet access:

- `cve_sample.json`
- `kev_sample.json`
- `rss_sample.xml`
- `github_sample.json`

Live fetching is disabled by default. Set `GREYNOC_FETCH_LIVE=true` only when
you intentionally want configured HTTP sources to be queried.

## Source Run History

Each ingest job records a structured `SourceRun` with source ID, status,
message, item count, start/end timestamps, and error details for failed runs.
Recent runs are available from:

```powershell
curl http://127.0.0.1:8000/ingest/runs
```

## Configuration

Source policy and seed registries live in `config/sources.yaml`. Scoring
defaults live in `config/scoring.yaml`. Secrets and local paths should be
supplied by environment variables or `.env`, using `.env.example` as a template.

Important environment variables:

- `GREYNOC_DATABASE_PATH`
- `GREYNOC_SOURCES_PATH`
- `GREYNOC_SCORING_PATH`
- `GREYNOC_FETCH_LIVE`
- `GREYNOC_GITHUB_TOKEN`
- `GREYNOC_LOG_LEVEL`

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
and `config/`.

## Current Limits

- The CLI currently exposes fixture ingest commands for CVE, KEV, and RSS.
  GitHub metadata ingest is available through the generic API/job path.
- Generated detections are drafts only until validated with representative
  telemetry.
- SQLite is the first storage backend; Postgres remains a planned extension.
- Live source fetching must be enabled deliberately with `GREYNOC_FETCH_LIVE`.

## Roadmap

- Add a CLI command for GitHub metadata ingest.
- Add Postgres storage behind the existing storage protocol.
- Add authenticated GitHub search adapter with rate-limit handling.
- Add asset inventory and affected-product popularity enrichment.
- Add validation workflows for promoting draft detections to validated status.

