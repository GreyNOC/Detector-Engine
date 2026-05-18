# GreyNOC Detector Engine

GreyNOC Detector Engine is a defensive, OSINT-driven, *predictive* threat
intelligence and detection-engine platform for SOC operators, defenders,
vulnerability analysts, and detection engineers.

It ingests public CVE, CISA KEV, vendor PSIRT, RSS/advisory/blog, news, GitHub
metadata, **FIRST.org EPSS exploit-prediction scores**, **abuse.ch ThreatFox
and URLhaus IOC feeds**, and **public ransomware leak-site metadata**;
normalizes source records; correlates weak signals; classifies AI-enabled
attack taxonomy terms; clusters threats into campaigns; attributes signals to
known public threat actors; and produces a forward-looking, fully explainable
`AttackForecast` per threat — probability, horizon, p50/p90 days, confidence,
and a list of named drivers. Threats are catalogued in a local SQLite-backed
library and draft detections (Sigma, Splunk, KQL, YARA) are generated for
SOC validation.

See `docs/predictive_engine.md` and `docs/osint_layer.md` for the full
architecture of the predictive overlay.

## What It Does Not Do

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

## Quickstart

```powershell
python -m pip install -e .[dev]
greynoc-detector init

# Authoritative + research feeds
greynoc-detector ingest cve --fixture data/fixtures/cve_sample.json
greynoc-detector ingest kev --fixture data/fixtures/kev_sample.json
greynoc-detector ingest rss --fixture data/fixtures/rss_sample.xml

# Predictive priors and OSINT IOC feeds
greynoc-detector ingest epss        --fixture data/fixtures/epss_sample.json
greynoc-detector ingest threatfox   --fixture data/fixtures/threatfox_sample.json
greynoc-detector ingest urlhaus     --fixture data/fixtures/urlhaus_sample.json
greynoc-detector ingest ransomwatch --fixture data/fixtures/ransomwatch_sample.json

# Correlate + predict (forecasts are computed inline)
greynoc-detector correlate
greynoc-detector predict run --asset-inventory config/asset_inventory.yaml
greynoc-detector threats list
greynoc-detector predict campaigns
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

