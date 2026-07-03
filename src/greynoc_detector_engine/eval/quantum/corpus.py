"""Labeled-corpus loading for the quantum-risk evaluation harness.

The corpus format is newline-delimited JSON (JSONL), one advisory per line::

    {"id": "ADV-001", "text": "OpenSSL TLS RSA key exchange ...",
     "products": ["openssl"], "hndl": 1, "vulnerable": 1}

Each row describes a single advisory snippet and its ground-truth labels under
the documented semantics of :class:`QuantumRiskClassifier`:

  * **vulnerable** -- ``1`` when the advisory concerns a quantum-vulnerable
    primitive (RSA, ECC, (EC)DH, and the protocols/libraries built on them);
    ``0`` for non-crypto issues (XSS, SQLi, ...) and pure PQC-awareness items.
  * **hndl** -- ``1`` when the advisory is a *harvest-now-decrypt-later* risk,
    i.e. a *confidentiality* primitive whose recorded traffic an adversary can
    decrypt once a CRQC exists. Signature-only forgery (ECDSA / RSA code
    signing) is ``vulnerable=1, hndl=0``; no crypto is ``vulnerable=0, hndl=0``.

The loader mirrors :mod:`greynoc_detector_engine.eval.corpus`: it is strict
about the two integer labels (a typo silently corrupts every metric) but
lenient about everything else -- blank lines are skipped, and a ``lenient``
caller can keep going past malformed rows. Duplicate ids are reported, never
silently dropped, because a corpus that repeats the same advisory inflates AUC.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_CORPUS = Path(__file__).resolve().parent / "data" / "quantum_corpus.jsonl"

_LABEL_STRINGS: dict[str, int] = {
    "true": 1,
    "yes": 1,
    "positive": 1,
    "1": 1,
    "false": 0,
    "no": 0,
    "negative": 0,
    "none": 0,
    "0": 0,
}


@dataclass(frozen=True)
class QuantumExample:
    """One labeled advisory snippet for the quantum-risk harness."""

    text: str
    products: list[str] = field(default_factory=list)
    hndl: int = 0  # 1 == harvest-now-decrypt-later (confidentiality primitive)
    vulnerable: int = 0  # 1 == quantum-vulnerable primitive referenced
    id: str = ""

    @property
    def hndl_name(self) -> str:
        return "hndl" if self.hndl == 1 else "not_hndl"


@dataclass
class QuantumCorpusStats:
    """Summary counts for a loaded quantum corpus."""

    n: int
    n_hndl: int
    n_not_hndl: int
    n_vulnerable: int
    n_not_vulnerable: int
    n_skipped: int
    duplicate_ids: int
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, object]:
        return {
            "n": self.n,
            "n_hndl": self.n_hndl,
            "n_not_hndl": self.n_not_hndl,
            "n_vulnerable": self.n_vulnerable,
            "n_not_vulnerable": self.n_not_vulnerable,
            "n_skipped": self.n_skipped,
            "duplicate_ids": self.duplicate_ids,
            "warnings": self.warnings,
        }


class CorpusError(ValueError):
    """Raised on a malformed corpus when not in lenient mode."""


def _coerce_label(raw: object, line_no: int, field_name: str) -> int:
    if isinstance(raw, bool):
        return 1 if raw else 0
    if isinstance(raw, int) and raw in (0, 1):
        return raw
    if isinstance(raw, float) and raw in (0.0, 1.0):
        return int(raw)
    key = str(raw).strip().lower()
    if key in _LABEL_STRINGS:
        return _LABEL_STRINGS[key]
    raise CorpusError(
        f"line {line_no}: {field_name} {raw!r} is not one of {sorted(set(_LABEL_STRINGS))} or 0/1"
    )


def _coerce_products(raw: object, line_no: int) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, list):
        return [str(item) for item in raw]
    raise CorpusError(f"line {line_no}: products {raw!r} must be a JSON array")


def _parse_row(row: dict[str, object], line_no: int) -> QuantumExample:
    if "text" not in row or "hndl" not in row or "vulnerable" not in row:
        raise CorpusError(f"line {line_no}: each row needs 'text', 'hndl' and 'vulnerable'")
    text = str(row["text"]).strip()
    if not text:
        raise CorpusError(f"line {line_no}: 'text' must be a non-empty string")
    return QuantumExample(
        text=text,
        products=_coerce_products(row.get("products"), line_no),
        hndl=_coerce_label(row["hndl"], line_no, "hndl"),
        vulnerable=_coerce_label(row["vulnerable"], line_no, "vulnerable"),
        id=str(row.get("id", "")),
    )


def load_quantum_corpus(
    path: str | Path, *, lenient: bool = False
) -> tuple[list[QuantumExample], QuantumCorpusStats]:
    """Load and validate a quantum corpus, returning the rows plus summary stats."""
    examples: list[QuantumExample] = []
    skipped = 0
    seen_id: Counter[str] = Counter()
    warnings: list[str] = []

    file_path = Path(path)
    with file_path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                row = json.loads(stripped)
                if not isinstance(row, dict):
                    raise CorpusError(f"line {line_no}: each row must be a JSON object")
                example = _parse_row(row, line_no)
            except (CorpusError, json.JSONDecodeError) as exc:
                if lenient:
                    skipped += 1
                    warnings.append(str(exc))
                    continue
                if isinstance(exc, json.JSONDecodeError):
                    raise CorpusError(f"line {line_no}: invalid JSON ({exc.msg})") from exc
                raise
            examples.append(example)
            if example.id:
                seen_id[example.id] += 1

    duplicate_ids = sum(count - 1 for count in seen_id.values() if count > 1)
    if duplicate_ids:
        warnings.append(f"{duplicate_ids} duplicate id(s) detected -- these inflate AUC")

    n_hndl = sum(1 for example in examples if example.hndl == 1)
    n_vuln = sum(1 for example in examples if example.vulnerable == 1)
    stats = QuantumCorpusStats(
        n=len(examples),
        n_hndl=n_hndl,
        n_not_hndl=len(examples) - n_hndl,
        n_vulnerable=n_vuln,
        n_not_vulnerable=len(examples) - n_vuln,
        n_skipped=skipped,
        duplicate_ids=duplicate_ids,
        warnings=warnings,
    )
    if warnings and lenient:
        print(f"corpus: {len(warnings)} warning(s) while loading", file=sys.stderr)
    return examples, stats
