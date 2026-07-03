"""Drive the quantum-risk evaluation harness over a labeled corpus.

:func:`evaluate_quantum_corpus` runs :class:`QuantumRiskClassifier` over every
advisory in the corpus and reports two views of its quality:

  * The **HNDL ranking** task -- treat ``assessment.score`` as a continuous
    harvest-now-decrypt-later score against the ``hndl`` label and reuse
    :func:`greynoc_detector_engine.eval.metrics.evaluate_scores` for the full
    ROC-AUC / TPR@FPR / F1 / calibration picture.
  * Two **boolean** decisions -- the classifier's ``harvest_now_decrypt_later``
    flag against ``hndl``, and its ``quantum_vulnerable`` flag against
    ``vulnerable`` -- each summarised as a small confusion matrix with
    precision / recall / F1.

Everything here is offline and pure-Python; the classifier is glass-box and
deterministic, so the report is reproducible.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from greynoc_detector_engine.analysis.quantum_risk import QuantumRiskClassifier
from greynoc_detector_engine.eval.metrics import EvaluationReport, evaluate_scores
from greynoc_detector_engine.eval.quantum.corpus import QuantumExample


@dataclass(frozen=True)
class ConfusionMatrix:
    """Confusion-matrix metrics for a boolean prediction vs. a boolean label."""

    name: str
    tp: int
    fp: int
    tn: int
    fn: int

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def accuracy(self) -> float:
        total = self.tp + self.fp + self.tn + self.fn
        return (self.tp + self.tn) / total if total else 0.0

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "tp": self.tp,
            "fp": self.fp,
            "tn": self.tn,
            "fn": self.fn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "accuracy": round(self.accuracy, 4),
        }


def _confusion(name: str, predictions: Sequence[bool], labels: Sequence[int]) -> ConfusionMatrix:
    tp = fp = tn = fn = 0
    for predicted, label in zip(predictions, labels, strict=True):
        positive = label == 1
        if predicted and positive:
            tp += 1
        elif predicted and not positive:
            fp += 1
        elif not predicted and not positive:
            tn += 1
        else:
            fn += 1
    return ConfusionMatrix(name=name, tp=tp, fp=fp, tn=tn, fn=fn)


@dataclass
class QuantumEvaluationReport:
    """The full quality picture for the classifier over one quantum corpus."""

    n: int
    hndl_ranking: EvaluationReport
    hndl_decision: ConfusionMatrix
    vulnerable_decision: ConfusionMatrix

    def as_dict(self) -> dict[str, object]:
        return {
            "n": self.n,
            "hndl_ranking": self.hndl_ranking.as_dict(),
            "hndl_decision": self.hndl_decision.as_dict(),
            "vulnerable_decision": self.vulnerable_decision.as_dict(),
        }


def evaluate_quantum_corpus(
    examples: Sequence[QuantumExample],
    *,
    name: str = "quantum_hndl",
    threshold: float = 0.5,
) -> QuantumEvaluationReport:
    """Run the classifier over the corpus and report ranking + decision metrics."""
    classifier = QuantumRiskClassifier()
    scores: list[float] = []
    hndl_labels: list[int] = []
    vuln_labels: list[int] = []
    hndl_predictions: list[bool] = []
    vuln_predictions: list[bool] = []

    for example in examples:
        assessment = classifier.assess(example.text, example.products)
        scores.append(assessment.score)
        hndl_labels.append(example.hndl)
        vuln_labels.append(example.vulnerable)
        hndl_predictions.append(assessment.harvest_now_decrypt_later)
        vuln_predictions.append(assessment.quantum_vulnerable)

    ranking = evaluate_scores(name, scores, hndl_labels, threshold=threshold)
    return QuantumEvaluationReport(
        n=len(examples),
        hndl_ranking=ranking,
        hndl_decision=_confusion("harvest_now_decrypt_later", hndl_predictions, hndl_labels),
        vulnerable_decision=_confusion("quantum_vulnerable", vuln_predictions, vuln_labels),
    )
