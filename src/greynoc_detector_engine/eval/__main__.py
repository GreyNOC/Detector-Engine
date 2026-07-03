"""``python -m greynoc_detector_engine.eval`` -- offline forecast evaluation.

A thin argv shim so the harness is runnable without the Typer CLI installed.
The richer entry point is ``gn eval ...`` (see ``cli/main.py``).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from greynoc_detector_engine.eval.corpus import load_forecast_corpus
from greynoc_detector_engine.eval.runner import (
    evaluate_forecast_corpus,
    fit_forecast_calibration,
    learn_fusion_weights,
)

_USAGE = (
    "usage: python -m greynoc_detector_engine.eval {report|calibrate|learn-weights} CORPUS.jsonl"
)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) < 2:
        print(_USAGE, file=sys.stderr)
        return 2
    command, corpus_path = args[0], args[1]
    examples, stats = load_forecast_corpus(Path(corpus_path), lenient="--lenient" in args)

    if command == "report":
        payload: dict[str, object] = {
            "corpus": stats.as_dict(),
            "report": evaluate_forecast_corpus(examples).as_dict(),
        }
    elif command == "calibrate":
        payload = {
            "corpus": stats.as_dict(),
            "calibration": fit_forecast_calibration(examples).as_dict(),
        }
    elif command == "learn-weights":
        payload = {
            "corpus": stats.as_dict(),
            "learned": learn_fusion_weights(examples).as_dict(),
        }
    else:
        print(_USAGE, file=sys.stderr)
        return 2

    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
