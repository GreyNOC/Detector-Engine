from __future__ import annotations

import pytest

from greynoc_detector_engine.eval.quantum import (
    DEFAULT_CORPUS,
    QuantumEvaluationReport,
    evaluate_quantum_corpus,
    load_quantum_corpus,
)
from greynoc_detector_engine.eval.quantum.corpus import (
    CorpusError,
    QuantumExample,
)
from greynoc_detector_engine.eval.quantum.corpus import (
    load_quantum_corpus as load_via_module,
)


def test_default_corpus_parses_with_both_classes() -> None:
    examples, stats = load_quantum_corpus(DEFAULT_CORPUS)
    assert len(examples) >= 30
    assert stats.n == len(examples)
    # Both classes present for each labeled dimension.
    assert stats.n_hndl > 0 and stats.n_not_hndl > 0
    assert stats.n_vulnerable > 0 and stats.n_not_vulnerable > 0
    assert stats.duplicate_ids == 0
    assert stats.n_skipped == 0


def test_default_corpus_is_loadable_via_package_export() -> None:
    examples, _ = load_via_module(DEFAULT_CORPUS)
    assert all(isinstance(example, QuantumExample) for example in examples)


def test_evaluate_quantum_corpus_separates_hndl() -> None:
    examples, _ = load_quantum_corpus(DEFAULT_CORPUS)
    report = evaluate_quantum_corpus(examples)
    assert isinstance(report, QuantumEvaluationReport)
    assert report.n == len(examples)

    auc = report.hndl_ranking.roc_auc
    assert auc is not None
    assert auc > 0.8

    assert report.hndl_decision.precision >= 0.7
    assert report.hndl_decision.recall >= 0.7


def test_evaluate_quantum_corpus_flags_vulnerable() -> None:
    examples, _ = load_quantum_corpus(DEFAULT_CORPUS)
    report = evaluate_quantum_corpus(examples)
    assert report.vulnerable_decision.precision >= 0.7
    assert report.vulnerable_decision.recall >= 0.7


def test_report_as_dict_is_serializable() -> None:
    examples, _ = load_quantum_corpus(DEFAULT_CORPUS)
    payload = evaluate_quantum_corpus(examples).as_dict()
    assert payload["n"] == len(examples)
    assert "hndl_ranking" in payload
    assert "hndl_decision" in payload
    assert "vulnerable_decision" in payload


def test_loader_coerces_string_and_bool_labels() -> None:
    examples, _ = load_quantum_corpus(DEFAULT_CORPUS)
    # Sanity: labels are normalized to ints 0/1.
    for example in examples:
        assert example.hndl in (0, 1)
        assert example.vulnerable in (0, 1)


def test_loader_rejects_bad_label(tmp_path: object) -> None:
    from pathlib import Path

    assert isinstance(tmp_path, Path)
    bad = tmp_path / "bad.jsonl"
    bad.write_text('{"text": "x", "hndl": 7, "vulnerable": 0}\n', encoding="utf-8")
    with pytest.raises(CorpusError):
        load_quantum_corpus(bad)


def test_loader_lenient_skips_malformed_rows(tmp_path: object) -> None:
    from pathlib import Path

    assert isinstance(tmp_path, Path)
    corpus = tmp_path / "mixed.jsonl"
    corpus.write_text(
        "\n"
        '{"text": "RSA TLS key exchange decryption", "hndl": 1, "vulnerable": 1}\n'
        "not json at all\n"
        '{"text": "XSS in a form", "hndl": 0, "vulnerable": 0}\n',
        encoding="utf-8",
    )
    examples, stats = load_quantum_corpus(corpus, lenient=True)
    assert len(examples) == 2
    assert stats.n_skipped == 1
