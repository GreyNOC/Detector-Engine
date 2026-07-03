# CLI Operator Guide

The GreyNOC CLI is designed for defensive SOC workflows. It reads from the same
SQLite-backed local library as the API and keeps outputs JSON-friendly for
shell pipelines, dashboards, and automation.

## Golden-path demo (offline)

```powershell
gn - workflow demo --pretty
```

Runs the end-to-end defensive workflow against the bundled fixtures under
`data/fixtures/`. No network access is required. The command initializes
local paths, ingests fixture-backed sources, correlates weak signals, runs
the predictive layer, and (unless `--skip-detections`) drafts detections.
The output is a compact JSON report of every step and the resulting counts
(ingest runs, CVEs, KEV entries, raw items, threats, campaigns, forecasts,
draft detections). Use this command to verify a new install before pointing
the engine at live sources.

## Quick status

```powershell
gn - status --pretty
```

Shows local counts for CVEs, KEV entries, raw items, threats, campaigns,
detections, forecasts, local network devices, intrusion signals, honeypot
events, detection status counts, severity counts, and the five most recent
ingest runs.

## Standard ingest workflow

```powershell
gn - ingest all --pretty
```

Runs the standard defensive ingest sequence across configured CVE, KEV, RSS,
EPSS, ThreatFox, URLhaus, and Ransomwatch sources. It continues past individual
source failures by default and returns a combined JSON result.

To stop after the first source failure:

```powershell
gn - ingest all --stop-on-error
```

To include allowlisted git repository ingestion:

```powershell
gn - ingest all --include-git
```

## Threat review

```powershell
gn - threats list --summary --limit 25 --pretty
gn - threats list --severity high --summary
gn - threats list --status new --summary
gn - threats list --query edgegateway --min-probability 0.5 --summary --pretty
gn - threats list --cve CVE-2026-12345 --product vpn --actor "Volt Typhoon" --summary
gn - threats top --limit 10 --min-probability 0.5 --pretty
gn - threats show thr-cve-cve-2026-12345 --pretty
```

`threats list` supports operator triage filters for free-text search, exact
CVE, product, actor, sector, campaign, forecast horizon, AI attack type, and
probability windows. `--sort` accepts `priority`, `probability`, `severity`,
`confidence`, `last_seen`, `first_seen`, or `title`.

`threats top` ranks threats by attack probability, severity, and predictive
score. It is meant to give an analyst a quick starting queue without adding any
offensive capability.

## Prediction review

```powershell
gn - predict imminent --min-probability 0.5 --limit 25 --pretty
gn - predict forecasts thr-cve-cve-2026-12345 --limit 25 --pretty
gn - predict campaigns --limit 25 --pretty
```

`predict imminent` mirrors the API's imminent/near-term view and returns compact
threat summaries.

## Detection review

```powershell
gn - detections list --summary --limit 25 --pretty
gn - detections list --status draft --kind sigma --summary
gn - detections list --threat-id thr-cve-cve-2026-12345 --summary
gn - detections show det-example --pretty
```

Generated detections remain drafts until validated with representative
telemetry. The CLI list/show commands are inspection tools only.

## Detection validation lifecycle

Validation requires structured evidence. The CLI refuses to validate a
detection without telemetry source, reviewer, positive sample size, and
true-positive count.

```powershell
gn - detections validate det-example `
    --telemetry-source splunk-lab `
    --reviewer grey-soc `
    --sample-size 100 `
    --true-positives 3 `
    --false-positives 0 `
    --summary "Validated against representative telemetry."
```

To deprecate a detection (e.g. a duplicate or low-quality rule), record a
documented reason:

```powershell
gn - detections reject det-example `
    --reviewer grey-soc `
    --reason "Duplicated by better Sigma rule."
```

To inspect a detection's quality passport (grade, trust score, blockers,
strengths) before approving:

```powershell
gn - detections quality det-example --pretty
```

## Job history

Every orchestrated worker run (ingest, correlate, predict, score,
detection-generation, workflow demo) is captured in a lightweight
`job_history` table. Inspect it with:

```powershell
gn - jobs list --limit 25 --pretty
gn - jobs list --job-type ingest:cve --pretty
gn - jobs show job-1234567890ab --pretty
```

The same data is exposed via the API at `GET /jobs` and `GET /jobs/{id}`.

## Local network and sensor review

```powershell
gn - network devices --limit 50 --pretty
gn - network ics --limit 50 --pretty
gn - sensor signals --limit 50 --pretty
gn - sensor honeypot-events --limit 50 --pretty
```

All list-style commands default to `--limit 100` and cap at `500` to avoid
accidental oversized terminal or automation output.
