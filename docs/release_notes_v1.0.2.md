# GreyNOC Detector Engine v1.0.2

GreyNOC Detector Engine v1.0.2 adds post-quantum readiness, cryptographic
posture analysis, a detection-quality evaluation harness, and richer threat
triage/search while preserving the public defensive-only research boundary.

## Install and Run

```bash
python -m pip install -e '.[dev]'
gn workflow demo --pretty
gn doctor crypto
```

The golden-path demo remains offline by default.

## Highlights

- **Post-quantum-ready artifact protection:** pure-stdlib LMS/HSS signing,
  hybrid signing envelopes, managed key rotation, transparency logging, and
  optional ML-DSA / ML-KEM backends.
- **Crypto posture analysis:** CBOM generation, TLS/X.509 posture checks,
  crypto inventory, Mosca harvest-now-decrypt-later analysis, and PQC migration
  planning.
- **Quantum-risk threat dimension:** `gn quantum scan` and read-only quantum API
  routes classify quantum-vulnerable cryptography in defensive intelligence.
- **Detection-quality harness:** offline forecast evaluation with ROC-AUC, fixed
  low-FPR TPR, F1, ECE/Brier, Platt calibration, and learned fusion weights.
- **Adversarial normalization hardening:** OSINT normalization strips zero-width
  and bidi controls and folds homoglyphs before entity extraction.
- **Threat triage search:** CLI and API threat search/filtering across text,
  CVEs, products, actors, sectors, campaigns, forecast horizon, AI attack type,
  and probability windows.

## Quality

- `pytest` passes 361 tests with 2 optional-backend skips.
- `ruff check src tests` passes.
- `ruff format --check src tests` passes.
- `mypy` passes under strict project settings.

## Defensive Boundary

No exploit generation, payload crafting, offensive scanning, credential theft,
persistence, bypass guidance, malware behavior, or abuse-enabling workflow has
been added or relaxed.

Generated detections remain drafts until validated with structured human
evidence.

## Suggested Release Body

Use the text above as the GitHub Release description for `v1.0.2`, or copy the
Highlights and Quality sections into the release body and link back to this file
for complete notes.
