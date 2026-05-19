# GreyNOC Detector Engine v1.0.1

GreyNOC Detector Engine v1.0.1 is a security hardening patch for the v1.0
operator-grade release. It preserves the defensive-only public demo and local
SOC-support workflow while tightening fetch, fixture, dependency, and typing
surfaces.

## Install and Run

```bash
python -m pip install -e '.[dev]'
gn workflow demo --pretty
```

The golden-path demo remains offline by default.

## Security Fixes

- **Redirect policy hardening:** the defensive HTTP client no longer delegates
  redirects to `httpx`. It follows redirects manually, revalidates each
  `Location` hop, and refuses cross-host redirects unless the destination is in
  `GREYNOC_ALLOWED_FETCH_HOSTS`.
- **Fixture read bounds:** fixture-backed JSON/text ingest checks file size
  against `GREYNOC_MAX_RESPONSE_BYTES` before reading into memory.
- **Dependency floor cleanup:** runtime and dev dependency floors were raised
  for FastAPI, Starlette, Uvicorn, idna, python-dotenv, and pytest.

## Quality

- Added regression tests for redirect allowlist enforcement and fixture size
  limits.
- Added `py.typed` so source-tree mypy checks can type-check the package.
- Verification at release: `python -m pytest` passes 167 tests,
  `python -m ruff check` passes, and `python -m mypy src\greynoc_detector_engine`
  passes.

## Defensive Boundary

No exploit generation, payload crafting, offensive scanning, credential theft,
persistence, evasion, bypass guidance, malware behavior, or abuse-enabling
workflow has been added or relaxed.

Generated detections remain drafts until validated with structured human
evidence.

## Suggested Release Body

Use the text above as the GitHub Release description for `v1.0.1`, or copy the
Security Fixes and Quality sections into the release body and link back to this
file for complete notes.
