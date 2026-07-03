from __future__ import annotations

import pytest

from greynoc_detector_engine.crypto import mldsa_available
from greynoc_detector_engine.crypto.kem import kem_available
from greynoc_detector_engine.crypto.selftest import (
    SelfTestReport,
    SelfTestResult,
    run_crypto_selftest,
)


def _by_name(report: SelfTestReport) -> dict[str, SelfTestResult]:
    return {result.name: result for result in report.results}


def test_report_is_ok_in_this_environment() -> None:
    report = run_crypto_selftest()
    # Optional crypto backends may be absent, but absence is reported as skip,
    # not failure.
    assert report.failed == 0
    assert report.ok is True


def test_counts_are_self_consistent() -> None:
    report = run_crypto_selftest()
    assert report.passed + report.failed + report.skipped == len(report.results)
    assert report.passed == sum(1 for r in report.results if r.status == "pass")
    assert report.failed == sum(1 for r in report.results if r.status == "fail")
    assert report.skipped == sum(1 for r in report.results if r.status == "skip")


def test_core_checks_pass() -> None:
    results = _by_name(run_crypto_selftest())
    # The always-available core: hashing, HMAC, and pure-stdlib LMS.
    assert results["hash.agility"].status == "pass"
    assert results["signing.hmac"].status == "pass"
    assert results["signing.lms"].status == "pass"
    expected_kem_status = "pass" if kem_available() else "skip"
    assert results["kem.roundtrip"].status == expected_kem_status


def test_there_is_a_passing_lms_check() -> None:
    report = run_crypto_selftest()
    lms_passes = [
        r for r in report.results if r.name.startswith("signing.lms") and r.status == "pass"
    ]
    assert lms_passes, "expected at least one passing LMS check"


def test_rfc8554_self_consistency_passes() -> None:
    results = _by_name(run_crypto_selftest())
    assert results["signing.lms.rfc8554"].status == "pass"


@pytest.mark.skipif(mldsa_available(), reason="ML-DSA backend (oqs) IS installed here")
def test_mldsa_is_skipped_when_backend_absent() -> None:
    results = _by_name(run_crypto_selftest())
    assert results["signing.mldsa"].status == "skip"


def test_every_result_has_a_valid_status() -> None:
    report = run_crypto_selftest()
    for result in report.results:
        assert result.status in {"pass", "fail", "skip"}
        if result.status == "fail":
            # A failing check must explain itself.
            assert result.detail


def test_as_dict_is_json_safe_and_carries_ok() -> None:
    report = run_crypto_selftest()
    payload = report.as_dict()
    assert payload["ok"] is True
    assert payload["failed"] == 0
    assert isinstance(payload["results"], list)
    assert payload["passed"] == report.passed
    # Round-trips back into the model without loss.
    restored = SelfTestReport.model_validate({k: v for k, v in payload.items() if k != "ok"})
    assert restored.ok == report.ok


def test_run_never_raises_and_is_repeatable() -> None:
    # Stateful LMS keys advance per call; running twice must still be clean.
    first = run_crypto_selftest()
    second = run_crypto_selftest()
    assert first.ok is True
    assert second.ok is True
    assert [r.name for r in first.results] == [r.name for r in second.results]
