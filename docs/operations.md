# Operations

## Setup

```powershell
python -m pip install -e .[dev]
copy .env.example .env
greynoc-detector init
```

## Configuration

Root configuration files:

- `config/sources.yaml`: source registry and GitHub monitoring keywords.
- `config/scoring.yaml`: default scoring weights and labels.

Environment variables use the `GREYNOC_` prefix. Live source fetching is off by
default with `GREYNOC_FETCH_LIVE=false`.

## Fixture Ingest

```powershell
greynoc-detector ingest cve --fixture data/fixtures/cve_sample.json
greynoc-detector ingest kev --fixture data/fixtures/kev_sample.json
greynoc-detector ingest rss --fixture data/fixtures/rss_sample.xml
```

Each ingest run is recorded with source id, status, item count, start time, end
time, and error details when a source fails. This gives operators a lightweight
audit trail without needing to scrape process logs.

## Correlation, Scoring, And Detections

```powershell
greynoc-detector correlate
greynoc-detector score
greynoc-detector threats list
greynoc-detector threats show thr-cve-cve-2026-12345
greynoc-detector detections generate thr-cve-cve-2026-12345
```

## API

```powershell
greynoc-detector serve --host 127.0.0.1 --port 8000
```

Core routes:

- `GET /health`
- `GET /sources`
- `GET /threats`
- `GET /threats/search`
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
- `POST /enrich/epss`
- `POST /correlate`
- `POST /correlate/run`
- `POST /detections/generate/{threat_id}`
- `POST /detections/{detection_id}/test`
- `PATCH /detections/{detection_id}/status`

Example run-history check:

```powershell
curl "http://127.0.0.1:8000/ingest/runs?limit=25"
```

Example threat triage search:

```powershell
curl "http://127.0.0.1:8000/threats/search?query=edgegateway&min_probability=0.5"
curl "http://127.0.0.1:8000/threats?cve=CVE-2026-12345&summary=true&sort=priority"
```

Example score-history and export checks:

```powershell
curl "http://127.0.0.1:8000/scores/events?target_id=thr-cve-cve-2026-12345"
curl "http://127.0.0.1:8000/exports/detections?status=validated&export_format=json"
```

Example intelligence summaries:

```powershell
curl "http://127.0.0.1:8000/intelligence/threats/thr-cve-cve-2026-12345/signal-dna"
curl "http://127.0.0.1:8000/intelligence/detections/det-example/quality-passport"
```

## Tests

```powershell
python -m pytest
ruff check .
ruff format --check .
mypy src
```

