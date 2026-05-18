# Implementation Plan

1. Build the framework skeleton, configuration system, typed models, source
   registry, storage abstraction, CLI shell, and API shell.
2. Implement offline CVE and CISA KEV ingestion through local fixtures and the
   same interfaces used for live feeds.
3. Add threat-library storage, deduplication, versioning, and searchable catalog
   operations over SQLite.
4. Add explainable scoring engines for exploitability, AI-abuse relevance,
   signal strength, and early warning.
5. Correlate CVEs, KEV records, source mentions, GitHub metadata, and AI attack
   taxonomy hits into versioned threat records.
6. Add RSS, blog, news, and GitHub metadata ingestion frameworks that preserve
   provenance and never execute untrusted content.
7. Generate draft defensive detections with assumptions, required telemetry,
   false-positive notes, and validation steps.
8. Wire the API and CLI to the same service/job layer.
9. Add Docker, documentation, examples, tests, linting, and type checking.
10. Self-review for defensive-only safety, broken imports, missing provenance,
    fake implementations, and weak explainability.

