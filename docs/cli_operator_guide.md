# CLI Operator Guide

The GreyNOC CLI is designed for defensive SOC workflows. It reads from the same
SQLite-backed local library as the API and keeps outputs JSON-friendly for
shell pipelines, dashboards, and automation.

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
gn - threats top --limit 10 --min-probability 0.5 --pretty
gn - threats show thr-cve-cve-2026-12345 --pretty
```

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

## Local network and sensor review

```powershell
gn - network devices --limit 50 --pretty
gn - network ics --limit 50 --pretty
gn - sensor signals --limit 50 --pretty
gn - sensor honeypot-events --limit 50 --pretty
```

All list-style commands default to `--limit 100` and cap at `500` to avoid
accidental oversized terminal or automation output.
