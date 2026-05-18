# Operations

## Setup

```powershell
python -m pip install -e .[dev]
copy .env.example .env
greynoc-engine init
```

## Configuration

Edit `src/greynoc_detection_engine/config/sources.yaml` to add or disable
sources. Keep secrets in environment variables. Live fetching is disabled until
`GREYNOC_FETCH_LIVE=true`.

## Ingest Jobs

```powershell
greynoc-engine ingest --source cve --fixture tests/fixtures/cve_sample.json
greynoc-engine ingest --source kev --fixture tests/fixtures/kev_sample.json
greynoc-engine ingest --source rss --fixture tests/fixtures/rss_sample.xml
```

## Correlation and Scoring

```powershell
greynoc-engine correlate
greynoc-engine score
```

## API

```powershell
greynoc-engine serve --host 127.0.0.1 --port 8000
```

Useful routes:

- `GET /health`
- `GET /sources`
- `GET /threats`
- `GET /cves`
- `GET /kev`
- `GET /detections`
- `POST /ingest/run?source=cve&fixture=tests/fixtures/cve_sample.json`
- `POST /correlate/run`

## Tests

```powershell
ruff check .
pytest
mypy src
```

## Adding Sources

Add a source entry to YAML. If the payload is RSS, CVE JSON, KEV JSON, or GitHub
repository metadata, existing ingestors can use it. For a new payload format,
create a `BaseIngestor` subclass and keep fixture coverage.

