# Groundbreaking Upgrades

After the security audit + fixes, we layered five capabilities that move
the engine from "tracks threats" to "learns, simulates, and exports to
the wider defender ecosystem".

## 1. Adaptive per-host scan baselines

`spacestation/adaptive.py` learns each remote address's normal "distinct
local ports touched" rate via an EWMA mean + variance. The scan detector
can now flag a *source* whose behavior jumps relative to *its own*
history, not just relative to a fixed threshold. This catches:

  * Low-and-slow scans that hide under the global threshold.
  * Hosts that "wake up" — e.g., a printer that suddenly starts touching
    23 ports, when its baseline is 2.
  * Bursty CI infrastructure that exceeds the global threshold harmlessly
    every build (we no longer page on it).

Baselines persist in SQLite (`scan_baselines` table) and decay after 30
days of silence.

## 2. Analyst feedback loop

`prediction/learning.py` turns SOC verdicts into updated fusion weights.
When an analyst marks a threat true-positive, the drivers that
contributed to that forecast get a small positive nudge; false-positives
nudge the opposite way. Per-step magnitude is capped so a single verdict
can't dominate, and weights are renormalized to keep total mass stable.

CLI:
```
greynoc-detector feedback submit <threat_id> --verdict true_positive
greynoc-detector feedback list
```
API:
```
POST /feedback   {threat_id, verdict, analyst, notes}
GET  /feedback
```

## 3. Forecast accuracy tracker

`prediction/accuracy.py` ingests `forecast_outcomes` rows and produces a
calibration report:

  * **Brier score** — mean squared error between probability and outcome.
  * **Accuracy@0.5** — fraction of predictions on the correct side.
  * **Per-bucket calibration** — does "0.7" actually mean ~70%?
  * **Per-horizon calibration** — are IMMINENT predictions calibrated?

The engine now knows when it is *wrong*, and the feedback tuner can act
on it.

CLI:
```
greynoc-detector predict record-outcome <threat_id> --attack
greynoc-detector predict accuracy
```

## 4. Counterfactual / what-if analysis

`prediction/counterfactual.py` answers "if I do X tomorrow, what does
the forecast become?" for the four most common SOC interventions:
`patch_applied`, `ioc_blocked`, `segmented`, `detection_deployed`.

CLI:
```
greynoc-detector predict counterfactual <threat_id> \
  --intervention patch_applied,ioc_blocked
```
API:
```
POST /predict/counterfactual/{threat_id}
```

## 5. STIX 2.1 + ATT&CK Navigator exporters

`exporters/stix.py` produces a standards-compliant STIX 2.1 bundle that
round-trips into MISP, OpenCTI, and any commercial TIP. Each threat
becomes a `report` plus `vulnerability` and `indicator` SCOs; campaigns
become `campaign` objects with `attributed-to` relationships to
`threat-actor` objects. Forecasts ride on the report as a namespaced
`x_greynoc_forecast` extension.

`exporters/attack_navigator.py` produces a Navigator JSON layer colored
by max predicted attack probability per technique. Drop the file into
the Navigator UI and the SOC sees a heat map of *predicted future*
techniques — not just historical ones.

CLI:
```
greynoc-detector export stix --out out/bundle.json
greynoc-detector export attack-navigator --out out/layer.json
```
API:
```
GET /export/stix
GET /export/attack-navigator
```

## Plus: reliability scaffolding

  * `storage/migrations.py` — versioned, idempotent SQLite migrations.
    `PRAGMA user_version` is the source of truth.
  * `workers/health.py` — `greynoc-detector doctor` runs a safety
    self-check (honeypot bind, HTTP caps); `doctor sources` reports
    source-feed health.

## Plus: speed scaffolding

  * SQLite is now opened in WAL mode with `synchronous=NORMAL` and a
    256 MiB mmap, materially reducing write contention while the sensor
    is hot.
  * `utils/cache.py` provides an ETag/Last-Modified-aware on-disk HTTP
    response cache; future ingest can wire it into `DefensiveHttpClient`
    for incremental fetches.
