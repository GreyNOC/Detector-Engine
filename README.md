# GreyNOC Detector Engine

GreyNOC Detector Engine is a defensive threat-intelligence and detection-engine
platform for SOC operators, defenders, vulnerability analysts, and detection
engineers.

It ingests public CVE, CISA KEV, RSS/advisory/blog, news, and GitHub metadata;
normalizes source records; correlates weak signals; tracks AI-enabled attack
taxonomy terms; scores exploitability and early-warning signals; catalogs
threats in a local SQLite-backed library; and generates explainable draft
detections for SOC validation.

## What It Does Not Do

This is not an offensive tool. It does not generate exploit code, malware,
credential-theft logic, persistence techniques, unauthorized scanning,
weaponized payloads, bypass instructions, or abuse-enabling procedures. GitHub
monitoring stores metadata only and never clones, downloads, installs, imports,
or executes untrusted code.

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
curl -X POST "http://127.0.0.1:8000/ingest/cve?fixture=data/fixtures/cve_sample.json"
curl -X POST "http://127.0.0.1:8000/correlate"
```

## Local Fixture Workflow

Fixtures in `data/fixtures/` let developers test ingest and correlation without
live internet access:

- `cve_sample.json`
- `kev_sample.json`
- `rss_sample.xml`
- `github_sample.json`

Live fetching is disabled by default. Set `GREYNOC_FETCH_LIVE=true` only when
you intentionally want configured HTTP sources to be queried.

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

## Source Configuration

Source policy and seed registries live in `config/sources.yaml`. Scoring defaults
live in `config/scoring.yaml`. Secrets and local paths should be supplied by
environment variables or `.env`, using `.env.example` as a template.

## Roadmap

- Add richer source-run history views and API endpoints.
- Add Postgres storage backend behind the existing storage protocol.
- Add authenticated GitHub search adapter with rate-limit handling.
- Add asset inventory and affected-product popularity enrichment.
- Add validation workflows for promoting draft detections to validated status.

