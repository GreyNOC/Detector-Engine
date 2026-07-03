# Post-Quantum Readiness

The engine treats the quantum transition from two sides:

1. **Protect its own artifacts** — crypto-agile, hybrid, post-quantum signing;
   hybrid KEM encryption; a managed keystore; and a tamper-evident, PQ-signed
   transparency log.
2. **Detect and prioritise** threats to *other* systems' cryptography — a
   quantum-risk classifier, a crypto-inventory scanner, a Mosca harvest-now-
   decrypt-later calculator, a CBOM emitter/parser, an X.509/TLS posture
   analyzer, and a CNSA-2.0 migration planner.

Everything is **offline-first** and **dependency-light**. The crucial property:
with **no optional extras installed at all**, the engine still has a *real
post-quantum public-key signature* (LMS/HSS, pure stdlib) — so `gn doctor crypto`
reports **post-quantum ready** out of the box. Optional extras add lattice PQC.

All algorithm facts (sizes, NIST categories, standards, deprecation dates) come
from one registry, `greynoc_detector_engine.crypto.algorithms`; see
[standards_reference.md](standards_reference.md) for the primary-source citations.

---

## 1. Protecting the engine's own artifacts

### 1.1 Hybrid, crypto-agile signing (`crypto/signing.py`)

Detection bundles and STIX exports are signed with a **detached, multi-algorithm
envelope**. A verifier needs only the artifact bytes and the envelope (asymmetric
components embed their own public key).

| Algorithm | Type | Quantum-safe? | Provides | Requires |
|-----------|------|---------------|----------|----------|
| `hmac-sha256` | symmetric MAC | **Yes** (Grover-only) | shared-key integrity | stdlib (always on) |
| `hss-lms` | **PQ hash-based sig** (RFC 8554 / SP 800-208) | **Yes** | **post-quantum non-repudiation** | **stdlib (always on)** |
| `ed25519` | classical asymmetric | No (Shor) | non-repudiation; hybrid half | `pq` extra (`cryptography`) |
| `ml-dsa-65` | PQ lattice sig (FIPS-204) | **Yes** | post-quantum non-repudiation | `pq-mldsa` extra (liboqs) |

`hss-lms` is the headline: a NIST-standardized, hash-based post-quantum signature
implemented in pure stdlib (`crypto/hbs.py`), validated against the RFC 8554
Test Case 1 known-answer vector. It is **stateful** — every one-time key signs
exactly once — so its private state must be persisted after each signature. The
**keystore** does this automatically; do not hand-roll LMS signing.

When a classical (Ed25519) and a post-quantum signature coexist the envelope is a
true **hybrid** — the CNSA-2.0 migration posture, secure as long as *either*
primitive holds.

```bash
gn crypto keygen --key-id primary            # creates an HMAC + LMS keyset in the keystore
gn crypto sign bundle.json --key-id primary  # writes bundle.json.sig.json (advances LMS state)
gn verify-signature bundle.json bundle.json.sig.json   # exit 0 ok, 2 on mismatch
gn export stix --out bundle.json --sign      # one-shot HMAC-signed STIX export
```

### 1.2 Managed keystore (`crypto/keystore.py`)

`gn crypto keys` / `keygen` / `rotate`. The keystore generates, persists (0600
where supported), rotates, and retires signing keys, and tracks `KeyMetadata`
(algorithm, state, public key, signatures remaining). It is the single place that
enforces the stateful-LMS rule: `sign_artifact` writes the advanced key state to
disk *before* returning the signature, so a crash can never reuse a one-time leaf.

### 1.3 Hybrid KEM artifact encryption (`crypto/kem.py`)

`gn crypto encrypt` / `decrypt`. Confidential artifacts are sealed with a hybrid
KEM: ephemeral **X25519** + **ML-KEM-768**, combined through HKDF-SHA256 into an
AES-256-GCM key. With an ML-KEM backend present the result is post-quantum
confidential; without one it degrades to classical X25519 and is clearly flagged
**not quantum-safe** (a harvest-now-decrypt-later risk), never silently.

### 1.4 Transparency log (`crypto/transparency.py`)

`gn crypto log`. An append-only Merkle log (RFC 6962-style domain separation) of
every published artifact, with **post-quantum-signed checkpoints** (signed tree
heads). Inclusion proofs show an artifact is in the log; any tampering with a past
entry changes the root, so a previously-signed checkpoint no longer matches.

Checkpoints are signed by a **persistent, pinnable** keystore key
(`transparency_log_key_id`, default `transparency-log`), not a throwaway key, so
the log has a stable well-known public key — `gn crypto log checkpoint` returns it
as `public_key`. **Authenticity requires pinning that key.** An asymmetric
signature embeds its own verification key, so without pinning the signature only
proves *internal consistency*: anyone can mint a fresh LMS key, sign a forged
root, and it self-verifies. `gn crypto log verify-checkpoint` therefore pins the
published key (`--pubkey`, or `--key-id` / the configured log key when the
keystore is local) and reports `authenticated`; a checkpoint signed by any other
key is rejected. The same pinning is available to any caller via
`HybridSigner.verify(..., expected_public_keys=...)`.

### 1.5 Crypto-agile hashing (`utils/hashing.py`)

Algorithm-selectable (`sha256` default, `sha3_256`, `blake2b`, …), refuses broken
primitives (MD5/SHA-1), and reports quantum resistance. 256-bit digests keep
~128-bit preimage strength under Grover — acceptable under NIST/CNSA-2.0.

### 1.6 Posture & self-test

```bash
gn doctor crypto      # hash, signing backends, KEM, TLS-KEM readiness, overall PQ-ready summary
gn crypto selftest    # known-answer / round-trip tests for every available backend
```

`gn doctor crypto` exits `0` whenever the engine is post-quantum ready — which
is the default, since the stdlib LMS/HSS backend always provides PQ
non-repudiation. Missing optional backends (liboqs ML-DSA, an ML-KEM library, or
an OpenSSL older than 3.5 for hybrid TLS) appear as informational `warn` findings
but do **not** flip the exit code; a non-zero exit is reserved for an actual loss
of PQ readiness. `gn crypto selftest` runs KATs for hashing, HMAC, LMS/HSS,
Ed25519 (if present), ML-DSA (if present), and the KEM.

---

## 2. Detecting threats to *other* systems' cryptography

### 2.1 Quantum-risk classifier (`analysis/quantum_risk.py`)

A glass-box, keyword-driven `QuantumRiskClassifier` scores threat text for
quantum-vulnerable primitives (RSA/ECC/DH, TLS/SSH/IPsec/PKI), harvest-now-
decrypt-later exposure, and CNSA-2.0 relevance, attaching an explainable
`QuantumRiskAssessment` to threats during normalization.

```bash
gn quantum scan "OpenSSL TLS RSA key exchange flaw; harvest now decrypt later" --product OpenSSL
```

Its quality is measured offline by an eval harness (`eval/quantum/`): `gn quantum
eval` reports ROC-AUC / F1 / precision-recall for the HNDL task against a labeled
advisory corpus.

### 2.2 Crypto inventory + Mosca (`analysis/crypto_inventory.py`, `analysis/mosca.py`)

```bash
gn quantum inventory assets.yaml       # posture summary + per-asset Mosca
gn quantum mosca --shelf-life 10 --migration 5 --crqc 8   # X + Y vs Z
```

Ingests a crypto inventory (YAML/JSON), maps each asset to the registry, and
produces a `CryptoPostureSummary` (vulnerable/safe counts, HNDL exposure,
readiness score). Mosca's inequality (`X + Y ≥ Z`) flags data that already cannot
be kept secret for its required lifetime.

### 2.3 CBOM (`analysis/cbom.py`, `models/cbom.py`)

```bash
gn crypto cbom --inventory assets.yaml --out cbom.json
```

Emits and ingests a **CycloneDX 1.6 Cryptographic Bill of Materials** —
`nistQuantumSecurityLevel` per asset, certificate/algorithm components, standard
`cryptoProperties`. Round-trippable into any CycloneDX-aware tool.

### 2.4 X.509 / TLS posture (`analysis/tls_posture.py`)

```bash
gn quantum cert server.pem             # classify a certificate's quantum exposure
```

Offline parsing (via `cryptography`) of an X.509 certificate or chain → public-key
and signature-algorithm quantum classification, with recommended PQ replacements.
An optional active TLS probe is **off by default** and SSRF-guarded.

### 2.5 Migration planner (`analysis/pqc_migration.py`)

```bash
gn quantum plan assets.yaml            # prioritized CNSA-2.0 migration plan
gn quantum timeline                    # CNSA 2.0 + NIST IR 8547 deadline reference
```

Ranks assets by HNDL exposure, Mosca margin, and NIST IR 8547 / CNSA-2.0
deadlines into a glass-box `MigrationPlan` with target algorithms and per-asset
urgency.

---

## 3. Optional extras

```bash
pip install -e '.[pq]'           # Ed25519 (classical) + X25519 for hybrid KEM
pip install -e '.[pq,pq-mldsa]'  # + FIPS-204 ML-DSA & ML-KEM via liboqs (build toolchain)
pip install -e '.[pq,pq-pure]'   # + pure-Python ML-KEM/ML-DSA (no C toolchain; reference-grade)
```

None of these are required: the stdlib LMS/HSS signer already provides
post-quantum non-repudiation, and HMAC provides quantum-safe integrity.

## 4. Safety boundary

None of this adds offensive capability. Signing/encryption protect defensive
artifacts; the analysis modules read public threat text, parse certificates, and
score inventories — they never perform cryptographic attacks, and the TLS probe
is off by default and host-validated. The lattice PQC libraries are optional and
isolated behind extras so the default install stays minimal and offline.
