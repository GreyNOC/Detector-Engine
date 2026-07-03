# Measuring and Improving Detection Quality

Detection quality is measurable, not vibes. This layer — ported from GreyNOC's
GN-SLOP-DETECTION research engine and retargeted onto attack forecasting — lets
you score the predictive layer against ground truth and harden ingest against
evasion. It is pure-Python, offline, and **never** runs at request time.

## Offline forecast-evaluation harness (`gn eval`)

The harness scores `AttackForecast` probabilities against a labeled corpus of
*realized* outcomes (positive class == "the threat was actually exploited") and
reports the metrics the forecasting literature uses:

- **ROC-AUC** — threshold-free separability.
- **TPR @ fixed FPR (1/5/10%)** — how much real attack you catch at a pinned,
  low false-positive budget. This is the number a triage queue actually cares
  about; reporting it forces the false-positive cost into the open.
- **Precision / recall / F1 / accuracy** at an operating threshold.
- **ECE / Brier** — calibration quality, when the score is read as a probability.

```bash
# Headline metrics (defaults to the bundled smoke corpus).
gn eval report --pretty
gn eval report path/to/outcomes.jsonl

# Fit Platt scaling so the fused score reads as a calibrated probability.
gn eval calibrate path/to/outcomes.jsonl

# Learn glass-box per-driver predictive_fusion_weights from realized outcomes.
gn eval learn-weights path/to/outcomes.jsonl --out weights.json
```

Corpus format is one JSON object per line:

```json
{"threat_id": "thr-...", "attack_probability": 0.82, "verified_attack": 1,
 "horizon": "near_term", "model": "horizon-1.1",
 "drivers": {"epss_probability": 0.6, "kev_listed": 1.0}}
```

The score is read from `attack_probability` / `score` / `forecast_probability`;
the label from `verified_attack` / `label` / `exploited`. The optional `drivers`
map (the forecaster's per-driver contributions) feeds weight learning — the
learned coefficients map one-to-one onto the names in
`config/scoring.yaml::predictive_fusion_weights`.

> The bundled `src/.../eval/data/seed_forecast_corpus.jsonl` is a **smoke-test
> set, not a benchmark.** Replace it with your own historical forecasts and
> their realized outcomes, and evaluate on a held-out split — the learner
> reports an optimistic train AUC only.

This complements the runtime outcome-bucket calibrator in
`prediction/calibration.py`: the calibrator tunes live probabilities from stored
outcomes; the harness *measures* the whole forecaster offline and proposes
weights/calibration for review.

## Adversarial-evasion resistance (`normalize/adversarial.py`)

A regex/lexicon entity extractor is trivially blinded by character-level tricks
that look identical to a human reader:

- **Zero-width / invisible** characters spliced inside words.
- **Homoglyph substitution** — Cyrillic/Greek lookalikes for Latin letters
  (NFKC does **not** fold these).
- **Bidi controls** (Trojan-Source family).
- **Exotic whitespace** that breaks tokenization or pads keyword density.

OSINT ingest now does the standard pairing: it **reports** the obfuscation as a
finding (mixed-script tokens and bidi controls are near-zero-false-positive
tells of deliberate tampering) and **defeats** it by stripping invisibles/bidi
and folding homoglyphs to ASCII *before* whitespace normalization and entity
extraction. A CVE id, product, or actor name hidden behind lookalike characters
therefore still matches, and feeds that injected the obfuscation are flagged.
