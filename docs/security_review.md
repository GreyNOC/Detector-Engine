# Security Review

A defensive audit of the engine's own attack surface. This document captures
findings + the fixes applied. We focus on bugs the *engine itself* could
introduce, not the trustworthiness of public feeds we ingest (those have
their own trust boundary documented in `osint_layer.md`).

## Threat model

| Adversary | Capability | Mitigation |
|---|---|---|
| Hostile public feed | Returns malicious JSON / RSS / git content | Pydantic `extra="forbid"`, content extension allowlist, no code execution, response size caps |
| Local network attacker | Sends scan / connection traffic to honeypot or our services | Honeypot binds loopback by default, per-source rate limit, sanitized payload preview |
| Anyone reachable to the API | Talks to FastAPI routes | CLI and Compose bind to `127.0.0.1` by default, production mutating routes require `GREYNOC_API_KEY`, fixture-path traversal blocked, list routes are bounded |
| Compromised configuration | Operator pastes a hostile URL into `sources.yaml` | URL shape strict, allowlist required for clones, redirect cap, no SSH/file/git URIs |
| Malicious git repo content | Symlinks, oversize blobs, hostile filenames | Walker skips symlinks, lstat for size, per-file and total caps, forbidden-extension blocklist |

## Findings (with disposition)

### HIGH

**H1. HTTP client had no redirect cap and no response size cap.**
*Files:* `utils/http.py`.
*Risk:* SSRF chains and memory exhaustion from a hostile feed.
*Fix:* Added `MAX_REDIRECTS = 5`, `DEFAULT_MAX_BYTES = 5_000_000`, streamed reads
that abort if the cap is exceeded. The same 5,000,000-byte default is used in
settings, `.env.example`, README, and this security review.

**H2. Git clone could be redirected by the remote server.**
*Files:* `ingest/git_clone.py`.
*Risk:* A server returning HTTP 30x could move the clone to an unallowlisted host.
*Fix:* Added `-c http.followRedirects=false` to the subprocess; the strict
URL shape regex now also rejects userinfo and IDN tricks.

**H3. Git clone target directory was predictable.**
*Files:* `ingest/git_clone.py`.
*Risk:* On a shared host an attacker could pre-create a symlink at the
predicted path; subsequent rmtree could follow it.
*Fix:* Each clone now lands in a unique per-call random subdirectory.
`cleanup()` resolves paths and refuses to delete anything that doesn't
live under `clone_root` after symlink resolution.

**H4. The git-repository walker followed symlinks.**
*Files:* `ingest/git_repository.py`.
*Risk:* A repo containing `symlink -> /etc/` could leak host files.
*Fix:* `os.walk(..., followlinks=False)`, file iteration uses `Path.lstat()`
to refuse symlink entries before reading.

**H5. The honeypot bound to 0.0.0.0 by default.**
*Files:* `spacestation/honeypot.py`.
*Risk:* On a multi-tenant or internet-reachable host the listener accepts
public traffic without operator opt-in.
*Fix:* Default is now `127.0.0.1`. A non-loopback bind requires
`allow_external_bind=True` and emits a startup log line listing the bind
target.

**H6. Honeypot had no per-source rate limit.**
*Files:* `spacestation/honeypot.py`.
*Risk:* A single attacker can flood the events table.
*Fix:* Token-bucket per `remote_address`, defaults to 30 events/minute, configurable.

**H7. API `fixture` query parameter allowed arbitrary local paths.**
*Files:* `api/routes/operations.py`, `api/routes/predictions.py`.
*Risk:* `?fixture=../../../etc/passwd` from any caller reachable to the API.
*Fix:* API ingest fixture paths resolve relative inputs under
`settings.fixture_root` and reject paths outside that root. Prediction asset
inventory paths accept the configured fixture/data roots and the optional
`GREYNOC_FIXTURE_DIR` compatibility root.

**H8. Mutating API routes could stay open when deployed without an API key.**
*Files:* `api/dependencies.py`, `docker-compose.yml`, `README.md`.
*Risk:* A production API exposed without `GREYNOC_API_KEY` allowed callers to
trigger ingest, correlation, prediction, detection generation, feedback, and
sensor operations.
*Fix:* `local`, `dev`, and `test` still allow no-key local development, but any
other `GREYNOC_ENV` fails closed unless `GREYNOC_API_KEY` is non-empty. Mutating
routes validate the `x-greynoc-api-key` header. Docker Compose sets
`GREYNOC_ENV=production`, requires `GREYNOC_API_KEY`, and binds host exposure to
`127.0.0.1:8000` by default.

### MEDIUM

**M1. Detection generators (Sigma/Splunk/Elastic/Defender) interpolated raw threat strings into rule queries.**
*Files:* `detection/*.py`.
*Risk:* A hostile threat title or product name with quotes/newlines could
corrupt the generated rule or sneak content past validation.
*Fix:* New `detection/safety.py::sanitize_rule_term()` strips control
characters, quotes, and SPL/KQL/YAML special tokens before insertion;
generators route every interpolation through it.

**M2. `arbitrary_types_allowed=True` on `PredictiveContext`.**
*Files:* `prediction/features.py`.
*Risk:* If anyone ever deserializes the model from untrusted JSON, custom
Python types could be instantiated.
*Fix:* Removed the flag; the model is now strict (all fields are typed
Pydantic primitives or known models).

**M3. Subprocess inherited too much of the parent environment.**
*Files:* `ingest/git_clone.py`.
*Risk:* A poisoned `HOME` with a malicious `.gitconfig` could change git
behavior (insteadOf rewrites, credential helpers).
*Fix:* `HOME` is now redirected to a clone-local scratch directory; we
explicitly clear `GIT_CONFIG_GLOBAL` and `GIT_CONFIG_SYSTEM` paths too.

**M4. Scan-detector port lists were unbounded.**
*Files:* `spacestation/scan_detector.py`.
*Risk:* A pathological connection table with millions of unique ports could
produce gigantic signal payloads and stall the scoring loop.
*Fix:* Per-signal port list is capped at 256 entries (sorted, deduped) and
`observation_count` carries the true count.

**M5. Honeypot payload preview accepted arbitrary bytes.**
*Files:* `spacestation/honeypot.py`.
*Risk:* Even after non-printable replacement, leaked credentials or PII
could survive in events.
*Fix:* Length-bounded, control-char-stripped, *and* high-entropy tokens are
redacted before storage (`payload_redact_high_entropy` config).

**M6. List endpoints were unbounded.**
*Files:* `api/routes/*.py`, `api/pagination.py`.
*Risk:* Large local datasets could produce oversized responses or slow API
calls.
*Fix:* Collection/list endpoints now accept `limit`, default to `100`, and cap
at `500`. Existing history endpoints keep the same bounds through the shared
pagination defaults.

**M7. Expensive API jobs could be launched repeatedly.**
*Files:* `api/job_locks.py`, `api/routes/*.py`.
*Risk:* Duplicate ingest, enrichment, correlation, prediction, detection, and
sensor operations could waste CPU/I/O or race each other.
*Fix:* Expensive POST operations use a per-process job lock and return
`409 Conflict` with a clear message when the same job is already running.

**M8. SQLite initialization ran during request dependency resolution.**
*Files:* `api/main.py`, `api/dependencies.py`.
*Risk:* Every request paid initialization/migration overhead and increased
contention risk.
*Fix:* FastAPI initializes SQLite once during app lifespan and stores the
`SQLiteStorage` instance on `app.state`. The dependency reuses that app-scoped
storage.

### LOW (accepted as documented design)

- API-key auth is intentionally a starter protection layer. Production still
  should use a reverse proxy or API gateway for TLS termination, logging,
  network policy, and full user/RBAC controls.
- API has no built-in rate limit. Documented; recommend running behind
  nginx/Envoy in any non-loopback deployment.

## How the audit is kept current

A `greynoc-detector doctor` command runs a self-check that re-verifies the
critical defaults at install time (honeypot bind, HTTP caps, redirect cap,
clone allowlist required, fixture root). It exits non-zero if any default
is unsafe.
