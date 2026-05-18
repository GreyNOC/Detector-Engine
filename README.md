# GreyNOC Detection Engine

`greynoc-detection-engine` is a defensive threat-intelligence and SOC-support
framework. It ingests source metadata, normalizes CVE and CISA KEV records,
correlates weak signals, produces explainable scores, catalogs threats, and
generates draft defensive detections.

The project deliberately stores defensive metadata only. It does not download,
execute, or generate exploit code, malware, credential-theft logic, persistence
logic, or abuse instructions.

## Current implementation slice

- Pydantic v2 models for sources, CVEs, KEV entries, threats, indicators,
  detections, and explainable score results.
- YAML source registry in `src/greynoc_detection_engine/config/sources.yaml`.
- SQLite storage abstraction with catalog operations.
- Fixture-capable CVE and KEV ingestors.
- RSS/news/blog and GitHub metadata ingestor frameworks.
- Explainable risk, exploitability, AI-abuse, signal, and early-warning scores.
- Correlation pipeline that links CVEs, KEV entries, source mentions, and AI
  attack taxonomy hits.
- Draft Sigma, YARA metadata, Suricata metadata, Splunk SPL, Elastic KQL, and
  Microsoft Defender KQL generators.
- FastAPI routes and Typer CLI commands.
- Unit and integration tests for the first working pipeline.

## Quick start

```powershell
python -m pip install -e .[dev]
greynoc-engine init
greynoc-engine ingest --source cve --fixture tests/fixtures/cve_sample.json
greynoc-engine ingest --source kev --fixture tests/fixtures/kev_sample.json
greynoc-engine correlate
greynoc-engine generate-detections
greynoc-engine serve
```

Run checks:

```powershell
ruff check .
pytest
mypy src
```

## Safety posture

The engine treats public exploit references as signals for defenders. It stores
URL/title/source metadata, affected products, exploit-availability context,
indicators, risk reasoning, and detection guidance. It does not clone or execute
untrusted repositories, and draft detections are marked unvalidated until tested
against known-good telemetry.

