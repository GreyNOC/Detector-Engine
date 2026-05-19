# Advanced Tool Roadmap

GreyNOC Detector Engine is past prototype. This page tracks what is now
considered *advanced-tool* quality versus what remains *future work*. It is
intentionally narrow: the engine is a defensive SOC-support tool, and any
roadmap item that would weaken that boundary is out of scope.

## Defensive boundary (non-negotiable)

The engine is defensive only. Roadmap items must never add:

- exploit generation, payload crafting, or weaponization,
- offensive scanning, credential theft, or persistence,
- detection evasion or bypass instructions,
- malware behavior or abuse-enabling functionality.

Detection generation stays draft / review-focused unless validated with
structured evidence.

## Now advanced (ready for SOC pilot use)

- **Repeatable golden-path demo.** `gn workflow demo` runs the full
  init → ingest → correlate → predict → detection-generation sequence
  offline against bundled fixtures. New installs verify with one command.
- **Structured detection validation.** `gn detections validate / reject /
  quality` require evidence (telemetry source, reviewer, sample size,
  TP/FP counts, summary). A detection cannot be marked `validated` without
  passing evidence, a reviewer, and a positive sample size.
- **Job history.** Every orchestrated run is recorded in `job_history`
  with status, timestamps, error, and a compact result summary. Surfaced
  via `gn jobs list / show` and `GET /jobs`.
- **Bounded list output.** All CLI and API list commands default to 100
  results and cap at 500, mirroring the API pagination helper.
- **Fail-closed defaults.** Live fetching is opt-in via
  `GREYNOC_FETCH_LIVE=true`. Untrusted code is never executed. Docker
  Compose binds API to loopback by default.
- **CI-friendly type and lint enforcement.** `ruff check`,
  `ruff format --check`, `mypy --strict`, and `pytest --cov` are green
  on every commit.

## Future work

- Optional Postgres backend (keep SQLite as default).
- Workflow scheduling beyond the existing APScheduler hooks (e.g. simple
  cron-equivalent persistence, retry policy) — without introducing
  Celery / Redis / external services.
- Detection automated test fixtures that exercise generated rules against
  PCAP / log samples and feed quality-passport precision-ready scores.
- A pluggable validation backend so SOC teams can route `validate` /
  `reject` events into ticketing systems.
- A first-class web UI for analyst review; today's UI surface is the CLI
  + JSON API.

## What we explicitly are not doing yet

- SaaS / multi-tenant deployment.
- External secrets management beyond environment variables.
- Generating offensive content of any kind, including for "testing".
- Auto-validating detections from automated runs alone — human evidence
  remains required.
