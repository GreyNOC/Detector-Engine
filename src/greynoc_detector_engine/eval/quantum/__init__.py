"""Offline quality harness for the :class:`QuantumRiskClassifier`.

This mirrors :mod:`greynoc_detector_engine.eval` but targets the post-quantum
risk dimension instead of attack forecasting. It loads a labeled corpus of
advisory snippets (:func:`load_quantum_corpus`) and scores the glass-box
classifier against the harvest-now-decrypt-later and quantum-vulnerable labels
(:func:`evaluate_quantum_corpus`), reusing the shared metric implementations.

It is a pure-Python offline tool and is **never** invoked at request time.
"""

from __future__ import annotations

from greynoc_detector_engine.eval.quantum.corpus import (
    DEFAULT_CORPUS,
    QuantumCorpusStats,
    QuantumExample,
    load_quantum_corpus,
)
from greynoc_detector_engine.eval.quantum.runner import (
    ConfusionMatrix,
    QuantumEvaluationReport,
    evaluate_quantum_corpus,
)

__all__ = [
    "DEFAULT_CORPUS",
    "ConfusionMatrix",
    "QuantumCorpusStats",
    "QuantumEvaluationReport",
    "QuantumExample",
    "evaluate_quantum_corpus",
    "load_quantum_corpus",
]
