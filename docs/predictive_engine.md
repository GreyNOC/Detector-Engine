# Predictive Engine

The predictive engine layers a forward-looking, OSINT-driven forecast on top
of the existing reactive aggregator. Every reactive ThreatRecord can be
augmented with an `AttackForecast` that says: *how likely* an attack is, *when*
it is expected to materialize, with *what confidence*, and *why*.

## Design tenets

1. **Probabilities, not verdicts.** The forecast emits a probability in
   `[0, 1]` and a coarse horizon bucket; the SOC still owns the decision.
2. **Explainability is mandatory.** Every probability ships with the named
   drivers that produced it, their normalized values, their weights, and
   contributions. Nothing is opaque.
3. **External priors carry more weight than internal heuristics.** When
   FIRST.org EPSS or CISA KEV speak, the engine listens; internal velocity is
   a tiebreaker, not a primary signal.
4. **No model training data is required.** The model is parametric and
   tuned by inspection. As historical hit data accumulates the same Pydantic
   feature contract supports swapping in a trained model behind the scenes.
5. **Defensive-only.** Same trust boundaries as the rest of the engine —
   metadata only, no code execution.

## Pipeline

```
+---------------+    +-----------------+    +-------------------+
| Reactive      |    | OSINT           |    | Predictive        |
| pipeline      |--->| enrichment      |--->| engine            |
| (CVE/KEV/RSS) |    | (EPSS, IOCs,    |    | (features ->      |
|               |    |  actors, asset) |    |  timing + weapon  |
|               |    |                 |    |  -> AttackForecast)|
+---------------+    +-----------------+    +-------------------+
                                                    |
                                                    v
                                              fused into RiskScorer
                                              + narratives + SOC ops
```

## Components

### Models (`models/prediction.py`)
- `AttackForecast` — probability, horizon, p50/p90 days, confidence, drivers.
- `EPSSScore` — FIRST.org point-in-time score and percentile.
- `CampaignCluster` — inferred cluster of related threats.
- `ThreatActorProfile` — small, public-attribution-only actor record.
- `VelocityBaseline` — z-scored chatter velocity for any keyed signal.

### Enrichment (`enrich/`)
- `epss.py` — pulls FIRST.org EPSS scores and joins them by CVE.
- `mitre_attack.py` — keyword-driven MITRE ATT&CK / ATLAS technique inference.
- `threat_actor.py` — public actor alias catalog and text attribution.
- `reputation.py` — aggregate IOC reputation from ThreatFox / URLhaus.
- `asset_context.py` — load your asset inventory and score target likelihood.

### Ingestors (`ingest/`)
- `epss.py` — FIRST.org EPSS JSON.
- `threatfox.py` — abuse.ch ThreatFox recent IOC JSON.
- `urlhaus.py` — abuse.ch URLhaus malicious URL feed.
- `ransomwatch.py` — public ransomware leak-site posts (metadata only).

### Analysis (`analysis/`)
- `baseline.py` — daily-bucketed mean+stddev with z-score anomaly flagging.
- `campaign.py` — overlap-based clustering on actors, CVEs, products, time.
- `trend.py` — short-vs-long-window velocity ratios.

### Prediction (`prediction/`)
- `features.py` — `PredictiveFeatures` (14 bounded features) and a
  `PredictiveFeatureBuilder` that assembles them from `PredictiveContext`.
- `exploit_timing.py` — hazard-style estimator for time-to-exploit; emits a
  `ForecastHorizon` (imminent / near_term / mid_term / long_term / unlikely)
  plus p50 and p90 days.
- `weaponization.py` — logistic estimator for "someone will operationalize
  this into a tool/RaaS playbook".
- `attack_forecast.py` — fuses everything into a single `AttackForecast`.

### Scoring (`scoring/`)
- `predictive.py` — converts an `AttackForecast` to a standard
  `ScoreResult` (so storage and downstream consumers see no schema changes).
- `risk.py` — re-weighted to make the predictive score dominate when it's
  available; falls back to the original reactive weighting otherwise.

## Predictive feature vector

All features are normalized to `[0, 1]`.

| feature | source | meaning |
| --- | --- | --- |
| `epss_probability` | EPSS | FIRST.org probability of exploit in 30 days |
| `epss_percentile` | EPSS | percentile rank across all CVEs |
| `kev_listed` | CISA KEV | already-known exploitation |
| `cvss_pressure` | NVD | severity / 10 |
| `public_exploit_availability` | NVD references | PoC / Metasploit / exploit-db |
| `chatter_velocity` | RSS/news/GitHub | short/long-window mention ratio |
| `independent_source_diversity` | source registry | # distinct trusted sources |
| `trusted_source_corroboration` | source registry | # high-confidence sources |
| `ransomware_proximity` | KEV + Ransomwatch + text | ransomware crew adjacency |
| `actor_activity` | actor attributor | named actors co-mentioned |
| `active_campaign` | campaign clusterer | inside an active cluster |
| `osint_ioc_corroboration` | ThreatFox / URLhaus | confirmed bad IOCs present |
| `ai_attack_relevance` | AI taxonomy | AI-enabled attack class |
| `recency` | timestamps | freshness decay over 90 days |

## CLI

```powershell
# One-time setup
greynoc-detector init

# Ingest enrichment priors
greynoc-detector ingest epss          --fixture data/fixtures/epss_sample.json
greynoc-detector ingest threatfox     --fixture data/fixtures/threatfox_sample.json
greynoc-detector ingest urlhaus       --fixture data/fixtures/urlhaus_sample.json
greynoc-detector ingest ransomwatch   --fixture data/fixtures/ransomwatch_sample.json

# Correlate + score (predictive layer runs inline)
greynoc-detector correlate

# Re-run only predictions (no re-ingest), optionally against an asset inventory
greynoc-detector predict run --asset-inventory config/asset_inventory.yaml

# Inspect
greynoc-detector predict forecasts thr-cve-cve-2026-12345
greynoc-detector predict campaigns
```

## API

```
POST /predict/run?asset_inventory=config/asset_inventory.yaml
GET  /predict/forecasts/{threat_id}
GET  /predict/threat/{threat_id}
GET  /predict/imminent?min_probability=0.5
GET  /campaigns
GET  /campaigns/{campaign_id}
```

## Tuning

All weights live in `config/scoring.yaml` under `predictive_fusion_weights`.
Hazard-model parameters live in `config/attack_horizon.yaml`. No code changes
are required to retune the engine.

## What this is *not*

- **Not** a model that predicts unknown zero-days from no signal. Real
  predictive value emerges only as OSINT signals accumulate around a CVE.
- **Not** a replacement for human triage. It produces a ranked list of
  candidates and explains each one — the SOC still validates.
- **Not** ML in the deep-learning sense. The model is a parametric, hand-
  tuned hazard + logistic fusion. The architecture is intentionally compatible
  with a learned drop-in replacement that consumes the same feature vector.
