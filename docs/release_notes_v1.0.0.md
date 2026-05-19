# GreyNOC Detector Engine v1.0.0

GreyNOC Detector Engine v1.0.0 is the first advanced, operator-grade release of the project. It moves the engine from advanced prototype to defensive SOC-support tool while preserving the public demo / research-engine boundary.

This release is intended for public demo use, local lab evaluation, and controlled SOC pilot review. It is not a production SaaS or multi-tenant SOC platform.

## Install and Run

```bash
python -m pip install -e '.[dev]'
gn workflow demo --pretty
```

The golden-path demo is offline by default. It initializes local paths, ingests bundled fixture-backed sources, correlates weak signals, runs the predictive layer, drafts detections, and prints a compact JSON report.

## Highlights

- **Golden-path demo:** `gn workflow demo` runs the end-to-end defensive workflow against bundled fixtures with no network access required.
- **Evidence-gated detection validation:** `gn detections validate` requires telemetry source, reviewer, sample size, true/false positive counts, and a summary before a detection can be marked validated.
- **Detection rejection workflow:** `gn detections reject` deprecates a rule with a documented reviewer and reason.
- **Detection quality passport:** `gn detections quality` reports grade, trust score, blockers, and strengths before approval.
- **Job history audit trail:** orchestrated worker runs are recorded in SQLite and exposed through `gn jobs list`, `gn jobs show`, `GET /jobs`, and `GET /jobs/{id}`.
- **API/CLI list-limit consistency:** list-style commands default to 100 results and cap at 500.
- **Forecasting performance pipeline:** prediction input fingerprinting skips recomputation when inputs have not changed; `--force` overrides this behavior.
- **Documentation refresh:** the operator guide, advanced-tool roadmap, security review, and README now point users toward the V1 workflow.

## Quality

- Ruff lint and format checks are part of CI.
- Strict mypy is part of CI.
- Pytest with coverage is part of CI.
- The V1.0 changelog records 164 passing tests and 78% coverage at release time.

## Defensive Boundary

No exploit generation, payload crafting, offensive scanning, credential theft, persistence, evasion, bypass guidance, malware behavior, or abuse-enabling workflow has been added in this release.

Generated detections remain drafts until validated with structured human evidence.

## Current Limits

- This is not a SaaS or multi-tenant deployment.
- SQLite is the default local backend; an optional Postgres backend remains future work.
- API-key authentication is a starter protection layer, not a full production identity or RBAC system.
- Non-loopback or production-style deployment should sit behind a reverse proxy or API gateway with TLS, logging, network policy, and user/RBAC controls.
- Live fetching is disabled by default and should only be enabled in controlled environments with appropriate source allowlists.
- Automated detection validation from generated runs alone remains out of scope; human evidence is required.

## Suggested Release Body

Use the text above as the GitHub Release description for `v1.0.0`, or copy the highlight list into the release body and link back to this file for complete notes.
