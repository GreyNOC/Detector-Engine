"""Emit, parse, and assess a CycloneDX 1.6 Cryptographic Bill of Materials.

This is the glass-box CBOM layer over the engine's crypto inventory. It turns a
list of :class:`~greynoc_detector_engine.models.crypto.CryptoAsset` into a
standards-conformant :class:`~greynoc_detector_engine.models.cbom.Cbom`
(:func:`generate_cbom` / :func:`to_json`), reconstructs assets from an ingested
document (:func:`parse_cbom`), and folds either form back into a posture summary
(:func:`assess_cbom`).

Everything here is offline and deterministic except the per-document
``serialNumber`` (a random UUID urn, as the CycloneDX spec intends). Algorithm
facts are never invented: parsing re-enriches each asset through
:meth:`CryptoAsset.from_algorithm` so a recognised name (e.g. ``ML-KEM-768``)
recovers its full registry posture rather than trusting the document.
"""

from __future__ import annotations

import json
import uuid
from typing import TYPE_CHECKING

from greynoc_detector_engine.crypto.algorithms import CryptoFamily
from greynoc_detector_engine.models.cbom import (
    FAMILY_TO_PRIMITIVE,
    AlgorithmProperties,
    Cbom,
    CbomComponent,
    CbomMetadata,
    CertificateProperties,
    CryptoAssetType,
    CryptoFunction,
    CryptoPrimitive,
    CryptoProperties,
)
from greynoc_detector_engine.models.crypto import CryptoAsset, CryptoAssetKind

if TYPE_CHECKING:
    from greynoc_detector_engine.models.crypto import CryptoPostureSummary

__all__ = [
    "assess_cbom",
    "generate_cbom",
    "parse_cbom",
    "to_json",
]


def _functions_for_family(family: CryptoFamily | None) -> list[CryptoFunction]:
    """The typical CycloneDX crypto-functions for an asset's family."""
    if family in (CryptoFamily.KEM, CryptoFamily.PUBLIC_KEY_ENCRYPTION):
        return [CryptoFunction.ENCAPSULATE, CryptoFunction.DECAPSULATE]
    if family is CryptoFamily.KEY_AGREEMENT:
        return [CryptoFunction.KEYDERIVE]
    if family is CryptoFamily.SIGNATURE:
        return [CryptoFunction.SIGN, CryptoFunction.VERIFY]
    if family in (CryptoFamily.SYMMETRIC,):
        return [CryptoFunction.ENCRYPT, CryptoFunction.DECRYPT]
    if family is CryptoFamily.MAC:
        return [CryptoFunction.TAG]
    if family is CryptoFamily.HASH:
        return [CryptoFunction.DIGEST]
    return []


def _algorithm_component(asset: CryptoAsset, *, bom_ref: str) -> CbomComponent:
    primitive = FAMILY_TO_PRIMITIVE.get(asset.family) if asset.family else None
    algo = AlgorithmProperties(
        primitive=primitive or CryptoPrimitive.UNKNOWN,
        parameterSetIdentifier=asset.algorithm or asset.parameter_set,
        cryptoFunctions=_functions_for_family(asset.family),
        classicalSecurityLevel=asset.classical_bits,
        nistQuantumSecurityLevel=asset.nist_quantum_category,
    )
    return CbomComponent(
        bom_ref=bom_ref,
        name=asset.identifier,
        cryptoProperties=CryptoProperties(
            assetType=CryptoAssetType.ALGORITHM,
            algorithmProperties=algo,
        ),
    )


def _certificate_component(asset: CryptoAsset, *, bom_ref: str) -> CbomComponent:
    cert = CertificateProperties(
        subjectName=asset.location,
        signatureAlgorithmRef=asset.algorithm,
        certificateFormat="X.509",
    )
    return CbomComponent(
        bom_ref=bom_ref,
        name=asset.identifier,
        cryptoProperties=CryptoProperties(
            assetType=CryptoAssetType.CERTIFICATE,
            certificateProperties=cert,
        ),
    )


def generate_cbom(
    assets: list[CryptoAsset],
    *,
    app_name: str = "greynoc-detector-engine",
    app_version: str = "1.0.2",
) -> Cbom:
    """Emit a CycloneDX 1.6 CBOM from a crypto inventory.

    Certificate assets become ``certificate`` components; everything else becomes
    an ``algorithm`` component. ``serialNumber`` is a fresh lowercase UUID urn.
    """
    components: list[CbomComponent] = []
    for index, asset in enumerate(assets):
        bom_ref = f"crypto-{index}-{asset.identifier}"
        if asset.kind is CryptoAssetKind.CERTIFICATE:
            components.append(_certificate_component(asset, bom_ref=bom_ref))
        else:
            components.append(_algorithm_component(asset, bom_ref=bom_ref))

    metadata = CbomMetadata(
        component={"type": "application", "name": app_name, "version": app_version}
    )
    return Cbom(
        serialNumber=f"urn:uuid:{uuid.uuid4()}",
        metadata=metadata,
        components=components,
    )


def to_json(cbom: Cbom) -> str:
    """Serialise a CBOM to JSON with hyphenated CycloneDX keys (``bom-ref``)."""
    return cbom.model_dump_json(by_alias=True, exclude_none=True)


def _asset_from_component(component: CbomComponent) -> CryptoAsset:
    props = component.cryptoProperties
    algo = props.algorithmProperties
    # Prefer the explicit parameter-set identifier (the registry name) then the
    # component name; re-enrich through the registry so a recognised algorithm
    # recovers its true quantum posture instead of trusting the document.
    candidates: list[str] = []
    if algo and algo.parameterSetIdentifier:
        candidates.append(algo.parameterSetIdentifier)
    candidates.append(component.name)

    kind = (
        CryptoAssetKind.CERTIFICATE
        if props.assetType is CryptoAssetType.CERTIFICATE
        else CryptoAssetKind.ALGORITHM
    )

    for candidate in candidates:
        rebuilt = CryptoAsset.from_algorithm(candidate, identifier=component.name, kind=kind)
        if rebuilt.algorithm is not None:
            return rebuilt

    # Unrecognised: keep what the document told us without inventing posture.
    return CryptoAsset(
        identifier=component.name,
        kind=kind,
        parameter_set=algo.parameterSetIdentifier if algo else None,
        classical_bits=algo.classicalSecurityLevel if algo else None,
        nist_quantum_category=(algo.nistQuantumSecurityLevel or 0) if algo else 0,
        source="cbom",
        notes=[f"{component.name!r} is not in the algorithm registry."],
    )


def parse_cbom(data: dict[str, object] | str) -> list[CryptoAsset]:
    """Ingest a CBOM document and rebuild the crypto-asset inventory."""
    payload = json.loads(data) if isinstance(data, str) else data
    cbom = Cbom.model_validate(payload)
    return [_asset_from_component(component) for component in cbom.components]


def assess_cbom(
    cbom_or_assets: Cbom | dict[str, object] | str | list[CryptoAsset],
) -> CryptoPostureSummary:
    """Fold a CBOM (or asset list) into a crypto-posture summary.

    The summariser is imported lazily so this module stays decoupled from the
    inventory analysis layer at import time.
    """
    from greynoc_detector_engine.analysis.crypto_inventory import build_posture_summary

    if isinstance(cbom_or_assets, Cbom):
        assets = parse_cbom(cbom_or_assets.model_dump(by_alias=True))
    elif isinstance(cbom_or_assets, list):
        assets = cbom_or_assets
    else:
        assets = parse_cbom(cbom_or_assets)
    return build_posture_summary(assets)
