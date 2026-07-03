"""Offline X.509 / TLS quantum-posture analyzer.

This module is *parse-only* and defensive. It inspects already-obtained
certificates and TLS handshake parameters and maps the cryptography they use to
the authoritative registry in
:mod:`greynoc_detector_engine.crypto.algorithms`, producing
:class:`~greynoc_detector_engine.models.crypto.CryptoAsset` records.

A certificate's public key is an *identity / signature* primitive: forging it
requires a cryptographically-relevant quantum computer at attack time, so the
asset is quantum-vulnerable but **not** harvest-now-decrypt-later (you cannot
retroactively forge a signature from recorded bytes). A TLS *key-exchange*
primitive is the opposite -- recorded handshakes are decryptable once a CRQC
exists -- so it is flagged HNDL.

An active probe (:func:`probe_tls_posture`) is provided but is **off by
default**: it raises unless ``allow_network=True`` and, when enabled, refuses
private / loopback / link-local / reserved hosts in the same conservative spirit
as :mod:`greynoc_detector_engine.utils.http`. The probe only *reads* the peer
certificate and negotiated protocol version; it never sends application data.
"""

from __future__ import annotations

import importlib.util
import ipaddress
import socket
import ssl
from typing import TYPE_CHECKING

from greynoc_detector_engine.models.crypto import CryptoAsset, CryptoAssetKind

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cryptography import x509

_SOURCE = "tls_posture"


def _require_cryptography() -> None:
    """Guard the optional ``cryptography`` dependency with an actionable message."""
    if importlib.util.find_spec("cryptography") is None:
        raise RuntimeError(
            "X.509/TLS posture analysis requires the 'cryptography' package; "
            "install it with: pip install '.[pq]'"
        )


# EC curve name (cryptography's ``curve.name``) -> registry algorithm name.
_EC_CURVE_TO_ALGORITHM: dict[str, str] = {
    "secp256r1": "ECDSA-P256",
    "secp384r1": "ECDSA-P384",
}

# Recognized TLS key-exchange tokens -> registry algorithm name. The mapped
# asset is a confidentiality primitive (HNDL).
_KEY_EXCHANGE_TO_ALGORITHM: dict[str, str] = {
    "ECDHE": "ECDH-P256",
    "X25519": "X25519",
    "DHE": "DH-2048",
    "RSA": "RSA-2048-KEX",
}


def _load_certificate(cert: bytes | str) -> x509.Certificate:
    """Parse a certificate from PEM (text or bytes) or DER (bytes)."""
    from cryptography import x509

    if isinstance(cert, str):
        return x509.load_pem_x509_certificate(cert.encode("ascii"))
    # bytes: PEM begins with the ASCII armor marker, otherwise treat as DER.
    if cert.lstrip().startswith(b"-----BEGIN"):
        return x509.load_pem_x509_certificate(cert)
    return x509.load_der_x509_certificate(cert)


def _common_name(name: x509.Name) -> str | None:
    from cryptography.x509.oid import NameOID

    attributes = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not attributes:
        return None
    value = attributes[0].value
    return value if isinstance(value, str) else value.decode("utf-8", errors="replace")


def _public_key_algorithm(certificate: x509.Certificate) -> str | None:
    """Map a certificate's public key to a registry algorithm name, if known."""
    from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa

    public_key = certificate.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        bits = public_key.key_size
        if bits <= 2048:
            return "RSA-2048"
        if bits <= 3072:
            return "RSA-3072"
        return "RSA-4096"
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return _EC_CURVE_TO_ALGORITHM.get(public_key.curve.name)
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519"
    if isinstance(public_key, ed448.Ed448PublicKey):
        return None
    return None


def analyze_certificate(cert: bytes | str) -> CryptoAsset:
    """Analyze one X.509 certificate's public-key quantum posture (parse-only).

    The returned asset is built from the registry, has ``kind=CERTIFICATE`` and
    is **not** harvest-now-decrypt-later (a certificate public key is a
    signature / identity primitive). Subject CN, issuer CN, ``notValidAfter``,
    and the certificate signature-algorithm OID are recorded in ``notes`` and
    ``location``.
    """
    _require_cryptography()
    certificate = _load_certificate(cert)

    subject_cn = _common_name(certificate.subject)
    issuer_cn = _common_name(certificate.issuer)
    not_after = certificate.not_valid_after_utc.isoformat()

    signature_oid = certificate.signature_algorithm_oid.dotted_string

    algorithm = _public_key_algorithm(certificate)
    location = f"subject CN={subject_cn or '?'}; issuer CN={issuer_cn or '?'}"

    if algorithm is None:
        public_key = certificate.public_key()
        label = type(public_key).__name__
        asset = CryptoAsset(
            identifier=f"certificate ({label})",
            kind=CryptoAssetKind.CERTIFICATE,
            location=location,
            source=_SOURCE,
            notes=[f"Unrecognized certificate public key type: {label}."],
        )
    else:
        asset = CryptoAsset.from_algorithm(
            algorithm,
            identifier=f"certificate public key ({algorithm})",
            kind=CryptoAssetKind.CERTIFICATE,
            location=location,
            source=_SOURCE,
        )
        # A certificate public key authenticates; it is not recordable plaintext.
        asset.harvest_now_decrypt_later = False

    asset.notes.append(f"notValidAfter={not_after}")
    asset.notes.append(f"signature algorithm OID={signature_oid}")
    return asset


def analyze_certificate_chain(certs: Sequence[bytes | str]) -> list[CryptoAsset]:
    """Analyze each certificate in a chain (leaf first by convention)."""
    return [analyze_certificate(cert) for cert in certs]


def classify_tls(version: str, key_exchange: str | None = None) -> list[CryptoAsset]:
    """Classify a TLS version and (optional) key-exchange method (parse-only).

    The protocol asset records the version (flagging anything below TLS 1.2 as
    weak). The key-exchange asset, when recognized, is a confidentiality
    primitive and is therefore flagged harvest-now-decrypt-later.
    """
    assets: list[CryptoAsset] = []

    normalized = version.strip()
    protocol = CryptoAsset(
        identifier=f"TLS protocol ({normalized})",
        kind=CryptoAssetKind.PROTOCOL,
        location=normalized,
        source=_SOURCE,
        notes=[f"Negotiated protocol: {normalized}."],
    )
    if _tls_is_weak(normalized):
        protocol.notes.append(
            "Protocol version below TLS 1.2 is deprecated (RFC 8996); upgrade required."
        )
    assets.append(protocol)

    if key_exchange is not None:
        token = key_exchange.strip().upper()
        algorithm = _KEY_EXCHANGE_TO_ALGORITHM.get(token)
        if algorithm is None:
            assets.append(
                CryptoAsset(
                    identifier=f"TLS key exchange ({key_exchange.strip()})",
                    kind=CryptoAssetKind.PROTOCOL,
                    location=normalized,
                    source=_SOURCE,
                    notes=[f"Unrecognized key-exchange method: {key_exchange.strip()!r}."],
                )
            )
        else:
            kex = CryptoAsset.from_algorithm(
                algorithm,
                identifier=f"TLS key exchange ({token})",
                kind=CryptoAssetKind.PROTOCOL,
                location=normalized,
                source=_SOURCE,
            )
            # Key exchange is a confidentiality primitive: recorded handshakes
            # are decryptable once a CRQC exists.
            if kex.quantum_vulnerable:
                kex.harvest_now_decrypt_later = True
            kex.notes.append("TLS key exchange establishes session secrets (confidentiality).")
            assets.append(kex)

    return assets


def _tls_is_weak(version: str) -> bool:
    """True for TLS/SSL versions below 1.2."""
    lowered = version.lower().replace(" ", "")
    weak_markers = ("sslv2", "sslv3", "ssl2", "ssl3", "tlsv1.0", "tls1.0", "tlsv1.1", "tls1.1")
    if any(marker in lowered for marker in weak_markers):
        return True
    # Bare "TLSv1" / "TLS 1" (no minor) is TLS 1.0.
    return lowered in {"tlsv1", "tls1", "tls1.0"}


def _ip_is_blocked(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True for any non-public address class (loopback/private/link-local/...)."""
    return any(
        (
            address.is_loopback,
            address.is_private,
            address.is_link_local,
            address.is_multicast,
            address.is_reserved,
            address.is_unspecified,
        )
    )


def _is_private_or_local_host(hostname: str) -> bool:
    """Conservative SSRF guard mirroring ``utils.http`` policy (parse-only)."""
    host = hostname.strip().rstrip(".").lower()
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".localhost"):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        labels = [label for label in host.split(".") if label]
        return bool(labels) and all(label.isdigit() or label.startswith("0x") for label in labels)
    return _ip_is_blocked(address)


def _resolve_public_address(host: str, port: int) -> str:
    """Resolve ``host`` and return a vetted public IP, or raise on SSRF risk.

    Resolving up front and connecting to the *vetted* address closes the
    DNS-rebinding / TOCTOU gap that a string-only hostname check leaves open: a
    name that resolves to a loopback / private / link-local / metadata address is
    refused before any socket is opened.
    """
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise RuntimeError(f"could not resolve host {host!r}: {exc}") from exc
    resolved = [str(info[4][0]) for info in infos]
    for ip_str in resolved:
        try:
            address = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if _ip_is_blocked(address):
            raise RuntimeError(
                f"refusing to probe {host!r}: it resolves to non-public address "
                f"{ip_str} (SSRF guard)."
            )
    if not resolved:
        raise RuntimeError(f"host {host!r} did not resolve to any address.")
    return resolved[0]


def probe_tls_posture(
    host: str,
    port: int = 443,
    *,
    allow_network: bool = False,
    timeout: float = 5.0,
) -> list[CryptoAsset]:
    """Actively read a peer's certificate + TLS version, then analyze it.

    Off by default: raises :class:`RuntimeError` unless ``allow_network=True``.
    When enabled, the host is validated against the same private / loopback /
    link-local / reserved policy as the defensive HTTP client before any socket
    is opened. The probe performs a TLS handshake purely to read the peer
    certificate (binary form) and negotiated protocol version; it sends no
    application data.
    """
    if not allow_network:
        raise RuntimeError(
            "probe_tls_posture is network-gated and disabled by default; "
            "pass allow_network=True to enable an outbound TLS probe."
        )

    _require_cryptography()
    if _is_private_or_local_host(host):
        raise RuntimeError(f"refusing to probe private/local host {host!r} (SSRF guard).")
    # Resolve and vet the actual address(es), then connect to the vetted IP so the
    # address we checked is the address we reach (no DNS-rebinding window).
    target_ip = _resolve_public_address(host, port)

    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    der_cert: bytes
    negotiated: str | None
    with (
        socket.create_connection((target_ip, port), timeout=timeout) as raw_sock,
        context.wrap_socket(raw_sock, server_hostname=host) as tls_sock,
    ):
        der = tls_sock.getpeercert(binary_form=True)
        if der is None:
            raise RuntimeError(f"peer {host}:{port} presented no certificate.")
        der_cert = der
        negotiated = tls_sock.version()

    assets: list[CryptoAsset] = []
    if negotiated is not None:
        assets.extend(classify_tls(negotiated))
    cert_asset = analyze_certificate(der_cert)
    cert_asset.location = f"{cert_asset.location or ''} @ {host}:{port}".strip()
    assets.append(cert_asset)
    return assets
