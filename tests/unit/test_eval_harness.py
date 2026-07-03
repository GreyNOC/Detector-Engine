from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from greynoc_detector_engine.cli.main import app
from greynoc_detector_engine.eval.corpus import (
    DEFAULT_CORPUS,
    CorpusError,
    ForecastExample,
    load_forecast_corpus,
)
from greynoc_detector_engine.eval.metrics import (
    brier_score,
    expected_calibration_error,
    roc_auc,
    tpr_at_fpr,
)
from greynoc_detector_engine.eval.platt import fit_platt
from greynoc_detector_engine.eval.runner import (
    evaluate_forecast_corpus,
    fit_forecast_calibration,
    learn_fusion_weights,
)


def test_roc_auc_perfect_and_constant() -> None:
    assert roc_auc([0.1, 0.2, 0.8, 0.9], [0, 0, 1, 1]) == 1.0
    # Constant scores -> no separability -> 0.5 (ties handled via average rank).
    assert roc_auc([0.5, 0.5, 0.5, 0.5], [0, 1, 0, 1]) == 0.5
    # Single-class corpus -> AUC undefined.
    assert roc_auc([0.1, 0.2], [1, 1]) is None


def test_tpr_at_fpr_zero_budget() -> None:
    scores = [0.1, 0.2, 0.3, 0.9]
    labels = [0, 0, 0, 1]
    # The single positive outscores every negative, so even a 0% FPR budget
    # catches it.
    assert tpr_at_fpr(scores, labels, 0.0) == 1.0


def test_calibration_metrics_reject_out_of_range_scores() -> None:
    # Raw, unbounded scores must not be read as probabilities.
    assert expected_calibration_error([1.5, -0.2], [1, 0]) is None
    assert brier_score([1.5, -0.2], [1, 0]) is None
    # In-range probabilities are accepted.
    assert brier_score([0.9, 0.1], [1, 0]) == pytest.approx(0.01, abs=1e-9)


def test_platt_scaling_maps_into_unit_interval() -> None:
    scores = [0.0, 1.0, 2.0, 3.0, 4.0, 5.0]
    labels = [0, 0, 0, 1, 1, 1]
    result = fit_platt(scores, labels)
    calibrated = [result.model.predict_proba([s]) for s in scores]
    assert all(0.0 <= p <= 1.0 for p in calibrated)
    # Higher raw score -> higher calibrated probability (monotone map).
    assert calibrated == sorted(calibrated)


def test_corpus_label_coercion_and_aliases() -> None:
    rows = [
        ForecastExample(score=0.8, label=1),
        ForecastExample(score=0.2, label=0),
    ]
    report = evaluate_forecast_corpus(rows)
    assert report.roc_auc == 1.0


def test_corpus_strict_vs_lenient(tmp_path: Path) -> None:
    corpus = tmp_path / "c.jsonl"
    corpus.write_text(
        '{"attack_probability": 0.8, "verified_attack": 1}\n'
        '{"attack_probability": 0.2, "label": "benign"}\n'
        "not json at all\n",
        encoding="utf-8",
    )
    with pytest.raises(CorpusError):
        load_forecast_corpus(corpus)
    examples, stats = load_forecast_corpus(corpus, lenient=True)
    assert len(examples) == 2
    assert stats.n_skipped == 1
    assert {e.label for e in examples} == {0, 1}


def test_seed_corpus_loads_and_separates() -> None:
    examples, stats = load_forecast_corpus(DEFAULT_CORPUS)
    assert stats.n == len(examples) > 0
    report = evaluate_forecast_corpus(examples)
    assert report.roc_auc is not None and report.roc_auc >= 0.9


def test_learn_fusion_weights_are_nonnegative_and_normalized() -> None:
    examples, _ = load_forecast_corpus(DEFAULT_CORPUS)
    learned = learn_fusion_weights(examples)
    suggested = learned.suggested_weights
    assert suggested
    assert all(value >= 0.0 for value in suggested.values())
    assert sum(suggested.values()) == pytest.approx(1.0, abs=1e-6)
    assert learned.train_auc is not None


def test_learn_fusion_weights_requires_drivers() -> None:
    with pytest.raises(ValueError, match="no 'drivers'"):
        learn_fusion_weights([ForecastExample(score=0.5, label=1)])


def test_fit_forecast_calibration_reports_n() -> None:
    examples, _ = load_forecast_corpus(DEFAULT_CORPUS)
    result = fit_forecast_calibration(examples)
    assert result.n == len(examples)


def test_eval_cli_report_and_learn_weights(tmp_path: Path) -> None:
    runner = CliRunner()
    report = runner.invoke(app, ["eval", "report", "--pretty"])
    assert report.exit_code == 0
    assert '"roc_auc"' in report.output

    out = tmp_path / "weights.json"
    learn = runner.invoke(app, ["eval", "learn-weights", "--out", str(out)])
    assert learn.exit_code == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert "suggested_predictive_fusion_weights" in payload
