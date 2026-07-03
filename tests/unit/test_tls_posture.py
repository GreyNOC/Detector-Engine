from __future__ import annotations

import datetime
import importlib.util

import pytest

_HAS_CRYPTOGRAPHY = importlib.util.find_spec("cryptography") is not None

pytestmark = pytest.mark.skipif(
    not _HAS_CRYPTOGRAPHY, reason="cryptography is required for X.509 / TLS posture analysis"
)

if _HAS_CRYPTOGRAPHY:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.hazmat.primitives.asymmetric.types import (
        CertificateIssuerPrivateKeyTypes,
        CertificatePublicKeyTypes,
    )
    from cryptography.x509.oid import NameOID

    from greynoc_detector_engine.analysis.tls_posture import (
        analyze_certificate,
        analyze_certificate_chain,
        classify_tls,
        probe_tls_posture,
    )
    from greynoc_detector_engine.models.crypto import CryptoAssetKind


def _self_signed(
    public_key: CertificatePublicKeyTypes,
    private_key: CertificateIssuerPrivateKeyTypes,
    *,
    cn: str,
) -> bytes:
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
    )
    cert = builder.sign(private_key, hashes.SHA256())
    return cert.public_bytes(encoding=serialization.Encoding.PEM)


def _rsa_2048_cert() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return _self_signed(key.public_key(), key, cn="rsa.example.test")


def _ec_p256_cert() -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    return _self_signed(key.public_key(), key, cn="ec.example.test")


def test_rsa_2048_certificate_is_quantum_vulnerable() -> None:
    asset = analyze_certificate(_rsa_2048_cert())
    assert asset.kind is CryptoAssetKind.CERTIFICATE
    assert asset.algorithm == "RSA-2048"
    assert asset.quantum_vulnerable is True
    assert asset.harvest_now_decrypt_later is False  # signature/identity, not HNDL
    assert asset.recommended_replacement  # non-empty
    assert any("notValidAfter" in note for note in asset.notes)
    assert any("signature algorithm OID" in note for note in asset.notes)
    assert "rsa.example.test" in (asset.location or "")


def test_ec_p256_certificate_is_quantum_vulnerable() -> None:
    asset = analyze_certificate(_ec_p256_cert())
    assert asset.algorithm == "ECDSA-P256"
    assert asset.quantum_vulnerable is True
    assert asset.harvest_now_decrypt_later is False
    assert asset.recommended_replacement


def test_analyze_certificate_accepts_der_bytes() -> None:
    pem = _rsa_2048_cert()
    cert = x509.load_pem_x509_certificate(pem)
    der = cert.public_bytes(encoding=serialization.Encoding.DER)
    asset = analyze_certificate(der)
    assert asset.algorithm == "RSA-2048"


def test_analyze_certificate_chain() -> None:
    assets = analyze_certificate_chain([_rsa_2048_cert(), _ec_p256_cert()])
    assert [a.algorithm for a in assets] == ["RSA-2048", "ECDSA-P256"]


def test_classify_tls_key_exchange_is_hndl() -> None:
    assets = classify_tls("TLS 1.2", "ECDHE")
    kex = [a for a in assets if "key exchange" in a.identifier]
    assert len(kex) == 1
    assert kex[0].algorithm == "ECDH-P256"
    assert kex[0].quantum_vulnerable is True
    assert kex[0].harvest_now_decrypt_later is True


def test_classify_tls_flags_weak_version() -> None:
    assets = classify_tls("TLSv1")
    protocol = assets[0]
    assert protocol.kind is CryptoAssetKind.PROTOCOL
    assert any("deprecated" in note.lower() for note in protocol.notes)


def test_classify_tls_modern_version_not_weak() -> None:
    assets = classify_tls("TLS 1.3")
    assert not any("deprecated" in note.lower() for note in assets[0].notes)


def test_classify_tls_rsa_key_exchange_is_hndl() -> None:
    assets = classify_tls("TLS 1.2", "RSA")
    kex = [a for a in assets if "key exchange" in a.identifier]
    assert kex[0].algorithm == "RSA-2048-KEX"
    assert kex[0].harvest_now_decrypt_later is True


def test_probe_refuses_without_allow_network() -> None:
    with pytest.raises(RuntimeError, match="network-gated"):
        probe_tls_posture("8.8.8.8", allow_network=False)


def test_probe_refuses_private_host_even_when_allowed() -> None:
    with pytest.raises(RuntimeError, match="private/local"):
        probe_tls_posture("127.0.0.1", allow_network=True)
