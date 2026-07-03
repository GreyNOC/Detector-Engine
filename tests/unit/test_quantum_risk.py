from __future__ import annotations

from typer.testing import CliRunner

from greynoc_detector_engine.analysis.quantum_risk import QuantumRiskClassifier
from greynoc_detector_engine.cli.main import app
from greynoc_detector_engine.models.cve import CVERecord
from greynoc_detector_engine.models.quantum import QuantumRiskLevel
from greynoc_detector_engine.models.threat import ThreatRecord
from greynoc_detector_engine.normalize.normalizer import ThreatNormalizer


def test_confidentiality_primitive_is_harvest_now_decrypt_later() -> None:
    a = QuantumRiskClassifier().assess(
        "OpenSSL TLS RSA key exchange flaw allows decryption of recorded session traffic"
    )
    assert a.risk_level is QuantumRiskLevel.HIGH
    assert a.harvest_now_decrypt_later is True
    assert "RSA" in a.affected_primitives
    assert a.cnsa_2_0_relevant is True


def test_explicit_harvest_language_is_critical() -> None:
    a = QuantumRiskClassifier().assess(
        "APT campaign harvest-now-decrypt-later: recording IPsec VPN traffic for future "
        "decryption once a CRQC exists"
    )
    assert a.risk_level is QuantumRiskLevel.CRITICAL
    assert a.score >= 0.9


def test_signature_only_is_moderate_not_hndl() -> None:
    a = QuantumRiskClassifier().assess("ECDSA signature forgery in code signing certificate")
    assert a.risk_level is QuantumRiskLevel.MODERATE
    assert a.harvest_now_decrypt_later is False


def test_awareness_without_primitive_is_low() -> None:
    a = QuantumRiskClassifier().assess(
        "Vendor announces post-quantum readiness plan aligned to CNSA 2.0 and ML-KEM"
    )
    assert a.risk_level is QuantumRiskLevel.LOW
    assert a.quantum_vulnerable is False


def test_pqc_solution_terms_do_not_register_as_vulnerable_dsa() -> None:
    # ML-DSA / SLH-DSA are the post-quantum *solutions*; they must not be flagged
    # as the broken DSA primitive.
    a = QuantumRiskClassifier().assess("Migration to ML-DSA and SLH-DSA per FIPS 204 and FIPS 205")
    assert "DSA" not in a.affected_primitives
    assert a.quantum_vulnerable is False


def test_irrelevant_text_is_none() -> None:
    a = QuantumRiskClassifier().assess("Stored XSS in the comment field of a blog engine")
    assert a.risk_level is QuantumRiskLevel.NONE
    assert a.score == 0.0
    assert a.affected_primitives == []


def test_normalizer_attaches_quantum_risk_to_crypto_cve() -> None:
    crypto_cve = CVERecord(
        cve_id="CVE-2026-20001",
        description="RSA key exchange downgrade in TLS handshake permits passive decryption.",
        affected_products=["openssl:openssl"],
    )
    threat = ThreatNormalizer().from_cve(crypto_cve)
    assert threat.quantum_risk is not None
    assert threat.quantum_risk.harvest_now_decrypt_later is True

    benign_cve = CVERecord(
        cve_id="CVE-2026-20002",
        description="Path traversal in a file upload handler.",
    )
    assert ThreatNormalizer().from_cve(benign_cve).quantum_risk is None


def test_threat_record_with_quantum_risk_round_trips() -> None:
    crypto_cve = CVERecord(
        cve_id="CVE-2026-20003",
        description="Diffie-Hellman key agreement weakness in an IPsec VPN gateway.",
    )
    threat = ThreatNormalizer().from_cve(crypto_cve)
    assert threat.quantum_risk is not None
    restored = ThreatRecord.model_validate_json(threat.model_dump_json())
    assert restored.quantum_risk is not None
    assert restored.quantum_risk.risk_level == threat.quantum_risk.risk_level


def test_quantum_scan_cli() -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["quantum", "scan", "TLS RSA key exchange decryption flaw", "--product", "OpenSSL"],
    )
    assert result.exit_code == 0
    assert '"risk_level"' in result.output
    assert "harvest_now_decrypt_later" in result.output
