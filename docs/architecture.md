# Architecture

## Purpose

GreyNOC Detection Engine is a defensive SOC-support framework. It catalogs
emerging AI-enabled and traditional cyber threats by ingesting trusted public
metadata, normalizing records, correlating weak signals, scoring risk, and
generating draft detections for validation.

## Module Layout

- `config`: runtime settings and YAML source registry loading.
- `models`: Pydantic schemas for sources, CVEs, KEV entries, indicators,
  threats, scores, and detections.
- `ingest`: common `BaseIngestor` interface plus CVE, KEV, RSS/news/blog, and
  GitHub metadata ingestors.
- `normalize`: source item normalization, entity extraction, and AI attack
  taxonomy classification.
- `enrich`: defensive metadata enrichment for references, CVE/KEV context,
  GitHub metadata, and source reputation.
- `scoring`: explainable score engines.
- `catalog`: SQLite storage, threat library, deduplication, and versioning.
- `analysis`: correlation, trend, narrative, and SOC recommendation engines.
- `detection`: draft detection generators.
- `api`: FastAPI routes.
- `cli`: Typer commands.
- `workers`: reusable jobs and scheduler construction.

## Data Flow

Sources are declared in YAML. Ingestors load either a fixture or a configured
live source, normalize payloads into typed records, and store them locally.
Correlation links CVEs to KEV entries and source mentions. Scoring engines add
numeric results with reasons and contributing signals. The catalog stores the
versioned threat record and draft detections.

## Trust Boundaries

Network sources and GitHub repositories are untrusted. The engine stores
metadata, excerpts, source hashes, and references only. It does not clone,
download, import, execute, or transform untrusted code into runnable logic.

## Defensive Safety Design

Exploit references are stored as defensive context: URL, source, affected
product, exploit-availability status, and scoring evidence. Detection
generators produce drafts with validation requirements and conservative
assumptions. YARA and Suricata outputs are metadata-only until validated
telemetry or samples exist.

## Provenance

Every `SourceItem` and `SourceReference` includes source ID/name, URL, title,
author when available, publication time, fetch time, content hash, confidence,
and a bounded raw excerpt.

## Scoring Explainability

Scores use weighted factors and return a `ScoreResult` containing the numeric
score, label, reason list, contributing signals, and timestamp. This keeps
triage decisions inspectable and repeatable.

## Extension Points

Add sources in YAML, then implement a `BaseIngestor` subclass only when the
payload format is new. Add storage backends by implementing `StorageBackend`.
Add scoring factors by extending the relevant input model and preserving the
reason trail. Add detection outputs by implementing a generator that returns
`GeneratedDetection`.

