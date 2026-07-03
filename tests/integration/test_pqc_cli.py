from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from greynoc_detector_engine.cli.main import app
from greynoc_detector_engine.config.settings import get_settings
from greynoc_detector_engine.crypto.kem import kem_available

runner = CliRunner()


@pytest.fixture
def pqc_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("GREYNOC_KEYSTORE_PATH", str(tmp_path / "keystore.json"))
    monkeypatch.setenv("GREYNOC_TRANSPARENCY_LOG_PATH", str(tmp_path / "log.jsonl"))
    get_settings.cache_clear()
    try:
        yield tmp_path
    finally:
        get_settings.cache_clear()


def _ok(*args: str) -> str:
    result = runner.invoke(app, list(args))
    assert result.exit_code == 0, f"{args} -> {result.exit_code}: {result.output}"
    return result.output


def test_crypto_algorithms_registry_lists_cnsa_suite() -> None:
    payload = json.loads(_ok("crypto", "algorithms", "--cnsa"))
    names = {row["name"] for row in payload}
    assert {"ML-KEM-1024", "ML-DSA-87"} <= names
    assert all(row["cnsa_2_0"] for row in payload)


def test_crypto_selftest_passes_in_this_environment() -> None:
    report = json.loads(_ok("crypto", "selftest"))
    assert report["failed"] == 0
    statuses = {r["name"]: r["status"] for r in report["results"]}
    # LMS is pure stdlib -> must pass; ML-DSA needs liboqs -> skipped here.
    assert any("lms" in name and status == "pass" for name, status in statuses.items())
    assert statuses.get("signing.mldsa") == "skip"


def test_keystore_sign_verify_and_no_leaf_reuse(pqc_env: Path) -> None:
    artifact = pqc_env / "bundle.json"
    artifact.write_text('{"detections": [1, 2, 3]}', encoding="utf-8")

    meta = json.loads(_ok("crypto", "keygen", "--key-id", "primary"))
    assert meta["quantum_safe"] is True
    assert "hss-lms" in meta["algorithm"]

    _ok("crypto", "sign", str(artifact), "--key-id", "primary")
    verify = json.loads(_ok("verify-signature", str(artifact), str(artifact) + ".sig.json"))
    assert verify["ok"] is True
    assert verify["verified"]["hss-lms"] is True

    # A second sign (separate keystore load) must consume a different one-time leaf.
    second = pqc_env / "sig2.json"
    _ok("crypto", "sign", str(artifact), "--key-id", "primary", "--out", str(second))
    first_env = json.loads((Path(str(artifact) + ".sig.json")).read_text(encoding="utf-8"))
    second_env = json.loads(second.read_text(encoding="utf-8"))

    def _lms(env: dict[str, object]) -> str:
        components = env["components"]
        assert isinstance(components, list)
        return next(c["signature"] for c in components if c["algorithm"] == "hss-lms")

    assert _lms(first_env) != _lms(second_env)


@pytest.mark.skipif(
    not kem_available(),
    reason="cryptography (X25519 + AES-256-GCM) not installed",
)
def test_kem_encrypt_decrypt_round_trip(pqc_env: Path) -> None:
    plaintext = pqc_env / "secret.bin"
    plaintext.write_bytes(b"top-secret threat intelligence bundle")
    key = pqc_env / "kem.json"
    envelope = pqc_env / "enc.json"
    recovered = pqc_env / "dec.bin"

    _ok("crypto", "kem-keygen", "--out", str(key))
    _ok("crypto", "encrypt", str(plaintext), "--key", str(key), "--out", str(envelope))
    _ok("crypto", "decrypt", str(envelope), "--key", str(key), "--out", str(recovered))
    assert recovered.read_bytes() == plaintext.read_bytes()


def test_transparency_log_append_checkpoint_verify(pqc_env: Path) -> None:
    artifact = pqc_env / "bundle.json"
    artifact.write_text("payload", encoding="utf-8")
    _ok("crypto", "log", "append", "bundle", str(artifact))
    root = json.loads(_ok("crypto", "log", "root"))
    assert root["size"] == 1 and root["root"]

    checkpoint = pqc_env / "cp.json"
    minted = json.loads(_ok("crypto", "log", "checkpoint", "--out", str(checkpoint)))
    # The checkpoint is signed by a persistent, pinnable keystore key.
    assert minted["public_key"]
    verdict = json.loads(_ok("crypto", "log", "verify-checkpoint", str(checkpoint)))
    assert verdict["signature_ok"] is True
    assert verdict["root_matches_live_log"] is True
    # The configured log key is pinned by default, so the signature is authenticated.
    assert verdict["authenticated"] is True


def test_verify_checkpoint_rejects_a_forged_signing_key(pqc_env: Path) -> None:
    from greynoc_detector_engine.crypto.signing import HybridSigner, SigningKeyset, generate_keyset
    from greynoc_detector_engine.crypto.transparency import TransparencyLog

    artifact = pqc_env / "bundle.json"
    artifact.write_text("payload", encoding="utf-8")
    _ok("crypto", "log", "append", "bundle", str(artifact))
    minted = json.loads(_ok("crypto", "log", "checkpoint"))
    log_pubkey = minted["public_key"]

    # An attacker forges a checkpoint over the same root with their OWN LMS key.
    log = TransparencyLog(pqc_env / "log.jsonl")
    forged = log.sign_checkpoint(HybridSigner(generate_keyset(hmac=False, lms=True)))
    forged_path = pqc_env / "forged.json"
    forged_path.write_text(forged.model_dump_json(indent=2), encoding="utf-8")

    # Unpinned, the forgery would self-verify; pinned to the real published key it
    # is rejected with a non-zero exit.
    result = runner.invoke(
        app, ["crypto", "log", "verify-checkpoint", str(forged_path), "--pubkey", log_pubkey]
    )
    assert result.exit_code == 2, result.output
    verdict = json.loads(result.output)
    assert verdict["signature_ok"] is False
    assert verdict["authenticated"] is False
    # Sanity: the same forged checkpoint verifies under an empty pin (the gap).
    assert TransparencyLog.verify_checkpoint(forged, HybridSigner(SigningKeyset())) is True


def test_quantum_inventory_plan_and_cbom(pqc_env: Path) -> None:
    inventory = pqc_env / "assets.yaml"
    inventory.write_text(
        "assets:\n"
        "  - name: api-tls-cert\n"
        "    algorithm: RSA-2048\n"
        "    kind: certificate\n"
        "  - name: vpn-kex\n"
        "    algorithm: ECDH P-256\n"
        "  - name: data-at-rest\n"
        "    algorithm: AES-256-GCM\n"
        "  - name: future-kem\n"
        "    algorithm: ML-KEM-768\n",
        encoding="utf-8",
    )
    inv = json.loads(_ok("quantum", "inventory", str(inventory)))
    assert inv["summary"]["total_assets"] == 4
    assert inv["summary"]["quantum_vulnerable"] >= 2

    plan = json.loads(_ok("quantum", "plan", str(inventory), "--year", "2026"))
    assert plan["total_assets"] == 4
    buckets = ("immediate", "high", "medium", "low", "already_safe")
    assert sum(plan[b] for b in buckets) == 4

    cbom_out = pqc_env / "cbom.json"
    _ok("crypto", "cbom", "--inventory", str(inventory), "--out", str(cbom_out))
    cbom = json.loads(cbom_out.read_text(encoding="utf-8"))
    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["specVersion"] == "1.6"


def test_quantum_mosca_and_timeline() -> None:
    mosca = json.loads(
        _ok("quantum", "mosca", "--shelf-life", "10", "--migration", "7", "--crqc", "8")
    )
    assert mosca["at_risk"] is True

    timeline = json.loads(_ok("quantum", "timeline"))
    assert timeline["nsm10_endpoint_year"] == 2035
    assert "ML-DSA-87" in timeline["cnsa_2_0_suite"]


def test_quantum_eval_separates_the_corpus() -> None:
    report = json.loads(_ok("quantum", "eval"))
    assert report["corpus"]["n"] >= 30
    ranking = report["report"]["hndl_ranking"]
    assert ranking["roc_auc"] > 0.8
