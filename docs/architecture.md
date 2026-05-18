# Architecture

## Data Flow

1. Source definitions are loaded from `config/sources.yaml`.
2. Ingestors fetch local fixtures or live HTTP sources when explicitly enabled.
3. Raw items, CVEs, and KEV entries are persisted in SQLite.
4. Normalizers extract entities, CVE references, products, exploit wording, and
   AI attack taxonomy terms.
5. The correlation engine links CVEs to KEV entries, source references, AI
   attack terms, and exploit-availability signals.
6. Scoring engines produce explainable score objects.
7. The threat library stores versioned threat records.
8. Draft detection generators produce validation-ready Sigma, SPL, KQL, YARA
   metadata, and Suricata metadata outputs.

## Trust Boundaries

All public source data is untrusted. Source content is treated as evidence for
defensive triage, not as executable material. GitHub data is metadata-only.

## Module Responsibilities

- `config`: environment and YAML loading.
- `models`: Pydantic v2 schemas.
- `ingest`: source-specific ingestors behind a common interface.
- `normalize`: entity extraction and AI attack classification.
- `analysis`: correlation, trend, and SOC recommendation logic.
- `scoring`: explainable score engines.
- `storage`: SQLite backend behind a protocol.
- `catalog`: threat-library lifecycle, dedupe, and versioning.
- `detection`: draft detection generators.
- `api`: FastAPI endpoints.
- `cli`: Typer commands.

## Storage Design

SQLite stores `raw_items`, `cves`, `kev_entries`, `threats`, `detections`,
`source_runs`, and `score_events`. Each domain record is stored as validated
Pydantic JSON, keeping the first backend simple while preserving a clean
boundary for a future Postgres implementation.

## Scoring Explainability

Scores return `score`, `label`, `reasons`, `contributing_signals`, and
`timestamp`. The reason trail is meant to be readable by an analyst and stable
enough for tests.

## Future Extension Points

- Add new ingestors by implementing `BaseIngestor`.
- Add a Postgres backend by implementing `StorageBackend`.
- Add source-specific enrichers without changing core models.
- Promote draft detections only after validation evidence exists.

