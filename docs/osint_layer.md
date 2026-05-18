# OSINT Layer

This document catalogs every external open-source feed the engine consumes and
documents the trust boundary for each one. All feeds are public; no credentials
are required for the default configuration.

## Feeds

| Feed | Type | Used for | Notes |
| --- | --- | --- | --- |
| FIRST.org EPSS | `epss_json` | External exploit-probability prior | Daily; authoritative. |
| CISA KEV | `kev_json` | Confirmed exploitation | Verified. |
| NVD CVE | `cve_json` | Vulnerability ground truth | Verified. |
| abuse.ch ThreatFox | `threatfox_json` | IOC reputation (IP/domain/URL/hash) | Tagged with malware family. |
| abuse.ch URLhaus | `urlhaus_json` | Malicious-URL reputation | Tagged with threat type. |
| Ransomwatch | `ransomwatch_json` | Ransomware leak-site posts | Metadata only. |
| Vendor PSIRT (Cisco, Fortinet, MSRC, Palo Alto, VMware) | `rss` | Authoritative advisories | High-reliability. |
| Research blogs (Mandiant, Unit 42, Talos, Rapid7, Sophos, DFIR Report) | `rss` | Campaign / TTP reporting | High-reliability. |
| AI-security research (Trail of Bits, Wiz Research) | `rss` | AI-attack reporting | High-reliability. |
| GitHub repository metadata | `github_search` | PoC / detection-rule signal | **Metadata only — no clone, no execute.** |

## Trust boundary

- For `github_search` sources we **only** persist GitHub API metadata and
  **never** clone, install, import, or execute code.
- For `git_repository` sources (e.g. SigmaHQ/sigma) cloning is **opt-in,
  HTTPS-only, per-source-allowlisted, shallow, sandboxed, and content-only**.
  We never execute any file from a clone — we only read text files whose
  extension is on the per-source allowlist (yml/yara/rules/json/md/txt by
  default), subject to per-file and total size caps, and we delete the clone
  after ingestion unless `cleanup_after_ingest: false` is set.
- We **never** download payloads from leak-site or IOC feeds.
- We **only** persist the metadata required to score and correlate.
- All ingestors follow the `BaseIngestor` contract: fixture-first for tests,
  live fetching opt-in via `GREYNOC_FETCH_LIVE=true`.

### `git_repository` policy (from `config/sources.yaml > policy.git_clone`)

```yaml
git_clone:
  enabled: opt_in                     # disabled unless a source enables itself
  require_per_source_allowlist: true  # always enforced; no global allowlist
  https_only: true                    # ssh/git/file/scp URLs are refused
  shallow_only: true                  # --depth=1 --single-branch --no-tags
  no_submodules: true                 # --no-recurse-submodules
  content_only: true                  # text files only; never executed
  default_max_file_size_kb: 256
  default_max_total_size_mb: 100
  default_clone_timeout_s: 60
```

The `GitCloner` enforces all of these at the subprocess level: hooks are
disabled (`core.hooksPath=/dev/null`), credential prompts are neutered
(`GIT_TERMINAL_PROMPT=0`, `GIT_ASKPASS=echo`), `--filter=blob:none` is set,
and the clone is locked to a sandbox directory it is the only thing allowed
to delete. Forbidden extensions (`.py`, `.sh`, `.ps1`, `.exe`, `.dll`, ...)
are refused at the walker layer as belt-and-braces.

### CLI

```powershell
# Offline (test fixture pointing at an already-checked-out directory)
greynoc-detector ingest git --fixture data/fixtures/sample_rules_repo

# Live (opt-in; requires GREYNOC_FETCH_LIVE=true and a per-source allowlist)
$env:GREYNOC_FETCH_LIVE = "true"
greynoc-detector ingest git
```

## Why these feeds

Each feed answers a different question the predictive model needs:

- **Will this be exploited?** EPSS gives a calibrated 30-day prior.
- **Is it already being exploited?** CISA KEV is the ground truth.
- **What infrastructure is being used right now?** ThreatFox / URLhaus.
- **Who is currently active?** Ransomwatch and research-blog actor mentions.
- **How urgently?** Vendor PSIRT emergency-patch language.
- **What detections already exist?** GitHub metadata for sigma/yara/suricata.

Without these external priors a "predictive" engine is just a reactive engine
with a different name. The whole point is that the *outside world* shouts
about an attack well before it lands in your telemetry — the engine listens.
