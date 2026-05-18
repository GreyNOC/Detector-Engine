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
- `POST /correlate`
- `POST /detections/generate/{threat_id}`

Example run-history check:

```powershell
curl "http://127.0.0.1:8000/ingest/runs?limit=25"
```

## Tests

```powershell
python -m pytest
ruff check .
ruff format --check .
mypy src
```

