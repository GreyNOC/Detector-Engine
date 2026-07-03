# Post-Quantum Standards Reference

The engine's PQC layer is built on primary standards, not blog posts. This page
is the citation index for every algorithm, size, date, and policy the engine
encodes in `greynoc_detector_engine.crypto.algorithms` (the registry) and the
analysis/migration modules. When a number in the code disagrees with a standard,
the standard wins — file it as a bug.

## NIST PQC standards (finalized 2024-08-13)

| Standard | Algorithm | Predecessor | What it provides |
|----------|-----------|-------------|------------------|
| **FIPS 203** | ML-KEM (512 / 768 / 1024) | CRYSTALS-Kyber | Key encapsulation (confidentiality) |
| **FIPS 204** | ML-DSA (44 / 65 / 87) | CRYSTALS-Dilithium | Lattice digital signatures |
| **FIPS 205** | SLH-DSA (12 parameter sets) | SPHINCS+ | Stateless hash-based signatures |
| **FIPS 206** *(draft)* | FN-DSA (Falcon) | Falcon | Compact lattice signatures — **not finalized**, sizes provisional |

Key/ciphertext/signature byte sizes (registry-encoded):

- **ML-KEM** (pk / sk / ct / shared-secret): 512 → 800 / 1632 / 768 / 32; 768 → 1184 / 2400 / 1088 / 32; 1024 → 1568 / 3168 / 1568 / 32. Categories 1 / 3 / 5. NIST default: **ML-KEM-768**.
- **ML-DSA** (pk / sk / sig): 44 → 1312 / 2560 / 2420 (cat 2); 65 → 1952 / 4032 / 3309 (cat 3); 87 → 2592 / 4896 / 4627 (cat 5).
- **SLH-DSA** (pk = 2n, sk = 4n, sig): 128s 32/64/7856, 128f 32/64/17088 (cat 1); 192s 48/96/16224, 192f 48/96/35664 (cat 3); 256s 64/128/29792, 256f 64/128/49856 (cat 5). SHA2 and SHAKE variants share sizes.

## Stateful hash-based signatures (the engine's always-on PQ backend)

| Standard | Scheme | Notes |
|----------|--------|-------|
| **RFC 8554** / **NIST SP 800-208** | LMS / HSS | Implemented in pure stdlib (`crypto/hbs.py`). SHA-256, big-endian wire format. **Stateful** — every one-time key signs exactly once; reuse is catastrophic. |
| **RFC 8391** / **NIST SP 800-208** | XMSS / XMSS^MT | Registry-tracked; recognized for CNSA-2.0 firmware signing. |

LMS/HSS is hash-based, so its security rests only on SHA-256 — quantum-resistant
with no lattice assumptions. SP 800-208 §6.1 Appendix A key derivation keeps the
private state compact (identifier + seed + leaf counter). NIST's "approved"
status additionally requires a hardware module that never exports private state;
the engine's pure-Python implementation is therefore suitable for verification,
research, and self-protection — and is honest about that in `gn doctor crypto`.

## Migration policy and deadlines

### NSA CNSA 2.0 suite

AES-256, ML-KEM-1024, ML-DSA-87, LMS/XMSS (firmware signing, per SP 800-208),
SHA-384 / SHA-512. Transition grid (support+prefer → exclusive):

| Technology class | Prefer by | Exclusive by |
|------------------|-----------|--------------|
| Software & firmware signing | 2025 | 2030 |
| Web browsers / servers / cloud | 2025 | 2033 |
| Traditional networking (VPN/routers) | 2026 | 2030 |
| Operating systems | 2027 | 2033 |
| Niche equipment | 2030 | 2033 |

New national-security-system acquisitions must support CNSA 2.0 from **2027-01-01**;
NSM-10 sets **2035** as the government-wide endpoint.

### NIST IR 8547 (ipd) deprecation timeline

- **112-bit** classical public-key (RSA-2048, FFDH-2048, ECC-at-112): **deprecated after 2030**, **disallowed after 2035**.
- **≥128-bit** classical public-key (RSA-3072+, ECDSA/ECDH P-256/P-384, Ed25519): **disallowed after 2035** (straight to disallowed, no deprecation window).
- 112-bit symmetric (3DES, SHA-224): disallowed 2030. AES-128/192/256 and SHA-256+ remain acceptable (Grover only halves strength).

## Mosca's inequality (harvest-now-decrypt-later)

With **X** = data security shelf-life, **Y** = migration time, **Z** = years to a
cryptographically-relevant quantum computer (CRQC): data is already at risk when
**X + Y > Z** (the engine uses `≥` as the conservative planning boundary). The
migration budget before exposure is **Z − X**. Implemented in `analysis/mosca.py`.

CRQC arrival is uncertain. The Global Risk Institute / evolutionQ *Quantum Threat
Timeline* expert survey (2024, 32 experts) put the likelihood of a CRQC within 10
years at roughly **19–34%**, and within 5 years at **~14%** — rising year over
year. Combined with long data shelf-lives, X + Y > Z already holds for many
organizations today, which is the entire point of acting before Q-Day.

## CycloneDX 1.6 CBOM

The engine emits and ingests a Cryptographic Bill of Materials as standard
CycloneDX 1.6: crypto assets are components of `type: "cryptographic-asset"` with
a `cryptoProperties` block (`assetType`, `algorithmProperties`,
`certificateProperties`, `oid`). `nistQuantumSecurityLevel` (0–6) is taken from
the registry's NIST category. See `analysis/cbom.py` and `models/cbom.py`.

## Primary sources

- FIPS 203 / 204 / 205: <https://csrc.nist.gov/pubs/fips/203/final>, `/204/final`, `/205/final`
- RFC 8554 (LMS/HSS): <https://www.rfc-editor.org/rfc/rfc8554>
- RFC 8391 (XMSS): <https://www.rfc-editor.org/rfc/rfc8391>
- NIST SP 800-208: <https://csrc.nist.gov/pubs/sp/800/208/final>
- NIST IR 8547 ipd: <https://csrc.nist.gov/pubs/ir/8547/ipd>
- NSA CNSA 2.0 FAQ: <https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF>
- GRI/evolutionQ Quantum Threat Timeline: <https://globalriskinstitute.org/publication/quantum-threat-timeline/>
- CycloneDX 1.6 schema: <https://cyclonedx.org/docs/1.6/json/>
