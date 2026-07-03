# Forecast evaluation corpus

`seed_forecast_corpus.jsonl` is a **smoke-test set, not a benchmark.** It is a
small synthetic set of realized-outcome rows used to exercise the offline
evaluation harness (`gn eval` / `python -m greynoc_detector_engine.eval`) and to
keep its metrics deterministic in CI. Numbers computed against it are not a
statement about real forecast quality.

To measure real quality, replace it with your own corpus of historical
forecasts and their *realized* outcomes — one JSON object per line:

```json
{"threat_id": "thr-...", "attack_probability": 0.82, "verified_attack": 1,
 "horizon": "near_term", "model": "horizon-1.1",
 "drivers": {"epss_probability": 0.6, "kev_listed": 1.0}}
```

- **score** — read from `attack_probability` / `score` / `forecast_probability`.
- **label** — read from `verified_attack` / `label` / `exploited`. `1` / `true` /
  `"exploited"` is the positive class (the threat was actually attacked).
- **drivers** *(optional)* — the forecaster's per-driver contributions, used by
  `gn eval learn-weights` to fit glass-box `predictive_fusion_weights`.

A good corpus pulls labels from ground truth you trust (CISA KEV additions,
confirmed incident timelines, honeypot/telemetry hits) and is evaluated on a
**held-out** split — the bundled learner reports an optimistic train AUC only.
