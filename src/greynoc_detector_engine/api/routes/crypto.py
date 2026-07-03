"""Read-only post-quantum crypto endpoints.

Exposes the engine's own crypto posture, the algorithm registry, and the
self-test. Key generation, signing, and encryption are deliberately *not* exposed
over HTTP -- those are operator actions on the CLI (they touch private key state);
the API stays read-only and safe.
"""

from __future__ import annotations

from fastapi import APIRouter, Query

from greynoc_detector_engine.crypto import algorithms as alg
from greynoc_detector_engine.crypto import crypto_posture
from greynoc_detector_engine.crypto.selftest import run_crypto_selftest

router = APIRouter()


@router.get("/crypto/posture")
def get_crypto_posture() -> dict[str, object]:
    """Report the engine's post-quantum cryptographic posture."""
    posture = crypto_posture()
    payload = posture.model_dump(mode="json")
    payload["ready"] = posture.ready
    return payload


@router.get("/crypto/algorithms")
def list_algorithms(
    family: str | None = Query(default=None),
    cnsa: bool = Query(default=False),
    vulnerable: bool = Query(default=False),
) -> list[dict[str, object]]:
    """List the post-quantum algorithm registry."""
    records = alg.all_algorithms()
    if family is not None:
        records = tuple(r for r in records if r.family.value == family.strip().lower())
    if cnsa:
        records = tuple(r for r in records if r.cnsa_2_0)
    if vulnerable:
        records = tuple(r for r in records if r.quantum_vulnerable)
    return [
        {
            "name": r.name,
            "family": r.family.value,
            "standard": r.standard.value if r.standard is not None else None,
            "quantum_threat": r.quantum_threat.value,
            "quantum_safe": r.quantum_safe,
            "nist_category": r.nist_category,
            "classical_bits": r.classical_bits,
            "cnsa_2_0": r.cnsa_2_0,
            "deprecated_after": r.deprecated_after,
            "disallowed_after": r.disallowed_after,
            "replaces_with": list(r.replaces_with),
        }
        for r in records
    ]


@router.get("/crypto/selftest")
def crypto_selftest() -> dict[str, object]:
    """Run known-answer / round-trip self-tests for every available backend."""
    return run_crypto_selftest().as_dict()


@router.get("/crypto/timeline")
def crypto_timeline() -> dict[str, object]:
    """CNSA 2.0 + NIST IR 8547 migration timeline and the CNSA suite."""
    return {
        "nsm10_endpoint_year": alg.NSM10_ENDPOINT_YEAR,
        "cnsa_2_0_exclusive_year": alg.CNSA_2_0_EXCLUSIVE_YEAR,
        "cnsa_2_0_acquisition_gate_year": alg.CNSA_2_0_ACQUISITION_GATE_YEAR,
        "cnsa_2_0_timeline": alg.CNSA_2_0_TIMELINE,
        "cnsa_2_0_suite": [r.name for r in alg.cnsa_2_0_suite()],
    }
