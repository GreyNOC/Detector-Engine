"""Labeled-corpus loading for the forecast evaluation harness.

The corpus format is newline-delimited JSON (JSONL), one realized outcome per
line::

    {"threat_id": "...", "attack_probability": 0.82, "verified_attack": 1,
     "horizon": "near_term", "model": "horizon-1.1",
     "drivers": {"epss_probability": 0.6, "kev_listed": 1.0}}

Only the *score* and the *label* are required:

  * **score** -- the forecaster output under test, read from any of
    ``attack_probability`` / ``score`` / ``forecast_probability``. Higher means
    "more likely to be attacked".
  * **label** -- ground truth, read from ``verified_attack`` / ``label`` /
    ``exploited``. ``1`` / ``true`` / ``"exploited"`` is the positive class
    (the threat was actually attacked); ``0`` / ``false`` / ``"benign"`` is the
    negative class.

Optional fields let an analyst slice metrics by ``horizon`` or generating
``model`` version, and the optional ``drivers`` map (a forecaster's per-driver
contributions) feeds glass-box weight learning.

The loader is deliberately strict about labels (a typo'd label silently
corrupts every metric downstream) but lenient about everything else: blank
lines are skipped, and a ``lenient`` caller can keep going past malformed rows.
Duplicate threat ids are reported, never silently dropped, because a corpus
that accidentally repeats the same outcome inflates AUC.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_CORPUS = Path(__file__).resolve().parent / "data" / "seed_forecast_corpus.jsonl"

_SCORE_KEYS = ("attack_probability", "score", "forecast_probability")
_LABEL_KEYS = ("verified_attack", "label", "exploited")
_LABEL_STRINGS: dict[str, int] = {
    "exploited": 1,
    "attacked": 1,
    "true": 1,
    "positive": 1,
    "yes": 1,
    "1": 1,
    "benign": 0,
    "not_exploited": 0,
    "none": 0,
    "false": 0,
    "negative": 0,
    "no": 0,
    "0": 0,
}


@dataclass(frozen=True)
class ForecastExample:
    score: float  # forecaster output under test (higher == more attack-likely)
    label: int  # 1 == exploited (positive), 0 == benign (negative)
    threat_id: str = ""
    horizon: str = "unknown"
    model: str = ""
    drivers: dict[str, float] = field(default_factory=dict)

    @property
    def label_name(self) -> str:
        return "exploited" if self.label == 1 else "benign"


@dataclass
class ForecastCorpusStats:
    n: int
    n_positive: int
    n_negative: int
    n_skipped: int
    duplicate_ids: int
    by_horizon: dict[str, int] = field(default_factory=dict)
    by_model: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, object]:
        return {
            "n": self.n,
            "n_positive": self.n_positive,
            "n_negative": self.n_negative,
            "n_skipped": self.n_skipped,
            "duplicate_ids": self.duplicate_ids,
            "by_horizon": dict(sorted(self.by_horizon.items())),
            "by_model": dict(sorted(self.by_model.items())),
            "warnings": self.warnings,
        }


class CorpusError(ValueError):
    """Raised on a malformed corpus when not in lenient mode."""


def _coerce_label(raw: object, line_no: int) -> int:
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
        f"line {line_no}: label {raw!r} is not one of {sorted(set(_LABEL_STRINGS))} or 0/1"
    )


def _first_present(row: dict[str, object], keys: tuple[str, ...]) -> tuple[str, object] | None:
    for key in keys:
        if key in row:
            return key, row[key]
    return None


def _parse_row(row: dict[str, object], line_no: int) -> ForecastExample:
    score_entry = _first_present(row, _SCORE_KEYS)
    label_entry = _first_present(row, _LABEL_KEYS)
    if score_entry is None or label_entry is None:
        raise CorpusError(
            f"line {line_no}: each row needs a score ({'/'.join(_SCORE_KEYS)}) "
            f"and a label ({'/'.join(_LABEL_KEYS)})"
        )
    try:
        score = float(score_entry[1])  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise CorpusError(f"line {line_no}: score {score_entry[1]!r} is not a number") from exc
    label = _coerce_label(label_entry[1], line_no)

    raw_drivers = row.get("drivers", {})
    drivers: dict[str, float] = {}
    if isinstance(raw_drivers, dict):
        for name, value in raw_drivers.items():
            try:
                drivers[str(name)] = float(value)
            except (TypeError, ValueError):
                continue
    return ForecastExample(
        score=score,
        label=label,
        threat_id=str(row.get("threat_id", "")),
        horizon=str(row.get("horizon", "unknown")) or "unknown",
        model=str(row.get("model", "")),
        drivers=drivers,
    )


def load_forecast_corpus(
    path: str | Path, *, lenient: bool = False
) -> tuple[list[ForecastExample], ForecastCorpusStats]:
    """Load and validate a forecast corpus, returning the rows plus summary stats."""
    examples: list[ForecastExample] = []
    skipped = 0
    seen_id: Counter[str] = Counter()
    by_horizon: Counter[str] = Counter()
    by_model: Counter[str] = Counter()
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
            if example.threat_id:
                seen_id[example.threat_id] += 1
            by_horizon[example.horizon] += 1
            if example.model:
                by_model[example.model] += 1

    duplicate_ids = sum(count - 1 for count in seen_id.values() if count > 1)
    if duplicate_ids:
        warnings.append(f"{duplicate_ids} duplicate threat id(s) detected -- these inflate AUC")

    n_pos = sum(1 for example in examples if example.label == 1)
    stats = ForecastCorpusStats(
        n=len(examples),
        n_positive=n_pos,
        n_negative=len(examples) - n_pos,
        n_skipped=skipped,
        duplicate_ids=duplicate_ids,
        by_horizon=dict(by_horizon),
        by_model=dict(by_model),
        warnings=warnings,
    )
    if warnings and lenient:
        print(f"corpus: {len(warnings)} warning(s) while loading", file=sys.stderr)
    return examples, stats
