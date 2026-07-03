"""CycloneDX 1.6 Cryptographic Bill of Materials (CBOM) schemas.

These pydantic v2 models describe the subset of the CycloneDX 1.6 BOM format
that the post-quantum layer emits and ingests: a document whose components are
``cryptographic-asset`` entries carrying ``cryptoProperties``. They are a faithful
but deliberately narrow projection of ``bom-1.6.schema.json`` -- only the fields
the engine populates (algorithm and certificate assets) are modelled, so the
emitter and parser in :mod:`greynoc_detector_engine.analysis.cbom` stay glass-box
and offline.

The canonical mapping from the engine's own
:class:`greynoc_detector_engine.crypto.algorithms.CryptoFamily` onto the
CycloneDX ``primitive`` enum lives here as :data:`FAMILY_TO_PRIMITIVE`, so the
translation is defined exactly once.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from greynoc_detector_engine.crypto.algorithms import CryptoFamily
from greynoc_detector_engine.utils.time import utc_now


class CryptoPrimitive(StrEnum):
    """CycloneDX 1.6 ``algorithmProperties.primitive`` enum."""

    DRBG = "drbg"
    MAC = "mac"
    BLOCK_CIPHER = "block-cipher"
    STREAM_CIPHER = "stream-cipher"
    SIGNATURE = "signature"
    HASH = "hash"
    PKE = "pke"
    XOF = "xof"
    KDF = "kdf"
    KEY_AGREE = "key-agree"
    KEM = "kem"
    AE = "ae"
    COMBINER = "combiner"
    OTHER = "other"
    UNKNOWN = "unknown"


class CryptoFunction(StrEnum):
    """CycloneDX 1.6 ``algorithmProperties.cryptoFunctions`` enum."""

    GENERATE = "generate"
    KEYGEN = "keygen"
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"
    DIGEST = "digest"
    TAG = "tag"
    KEYDERIVE = "keyderive"
    SIGN = "sign"
    VERIFY = "verify"
    ENCAPSULATE = "encapsulate"
    DECAPSULATE = "decapsulate"
    OTHER = "other"
    UNKNOWN = "unknown"


class CryptoAssetType(StrEnum):
    """CycloneDX 1.6 ``cryptoProperties.assetType`` enum."""

    ALGORITHM = "algorithm"
    CERTIFICATE = "certificate"
    PROTOCOL = "protocol"
    RELATED_CRYPTO_MATERIAL = "related-crypto-material"


# Canonical CryptoFamily -> CycloneDX primitive mapping (defined exactly once).
FAMILY_TO_PRIMITIVE: dict[CryptoFamily, CryptoPrimitive] = {
    CryptoFamily.KEM: CryptoPrimitive.KEM,
    CryptoFamily.KEY_AGREEMENT: CryptoPrimitive.KEY_AGREE,
    CryptoFamily.PUBLIC_KEY_ENCRYPTION: CryptoPrimitive.PKE,
    CryptoFamily.SIGNATURE: CryptoPrimitive.SIGNATURE,
    CryptoFamily.SYMMETRIC: CryptoPrimitive.BLOCK_CIPHER,
    CryptoFamily.MAC: CryptoPrimitive.MAC,
    CryptoFamily.HASH: CryptoPrimitive.HASH,
}


class AlgorithmProperties(BaseModel):
    """CycloneDX 1.6 ``cryptoProperties.algorithmProperties``."""

    model_config = ConfigDict(extra="forbid")

    primitive: CryptoPrimitive | None = None
    parameterSetIdentifier: str | None = None
    curve: str | None = None
    mode: str | None = None
    padding: str | None = None
    cryptoFunctions: list[CryptoFunction] = Field(default_factory=list)
    classicalSecurityLevel: int | None = None
    nistQuantumSecurityLevel: int | None = Field(default=None, ge=0, le=6)


class CertificateProperties(BaseModel):
    """CycloneDX 1.6 ``cryptoProperties.certificateProperties``."""

    model_config = ConfigDict(extra="forbid")

    subjectName: str | None = None
    issuerName: str | None = None
    notValidBefore: str | None = None
    notValidAfter: str | None = None
    signatureAlgorithmRef: str | None = None
    subjectPublicKeyRef: str | None = None
    certificateFormat: str | None = None


class CryptoProperties(BaseModel):
    """CycloneDX 1.6 ``component.cryptoProperties``."""

    model_config = ConfigDict(extra="forbid")

    assetType: CryptoAssetType
    algorithmProperties: AlgorithmProperties | None = None
    certificateProperties: CertificateProperties | None = None
    oid: str | None = None


class CbomComponent(BaseModel):
    """A CycloneDX ``cryptographic-asset`` component."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    type: str = "cryptographic-asset"
    bom_ref: str = Field(alias="bom-ref", serialization_alias="bom-ref")
    name: str
    cryptoProperties: CryptoProperties


class CbomMetadata(BaseModel):
    """CycloneDX ``metadata`` (timestamp + a thin tool/component descriptor)."""

    model_config = ConfigDict(extra="forbid")

    timestamp: datetime = Field(default_factory=utc_now)
    component: dict[str, str] = Field(default_factory=dict)


class Cbom(BaseModel):
    """A CycloneDX 1.6 Cryptographic Bill of Materials document."""

    model_config = ConfigDict(extra="forbid")

    bomFormat: str = "CycloneDX"
    specVersion: str = "1.6"
    serialNumber: str
    version: int = 1
    metadata: CbomMetadata = Field(default_factory=CbomMetadata)
    components: list[CbomComponent] = Field(default_factory=list)
    dependencies: list[dict[str, object]] = Field(default_factory=list)
