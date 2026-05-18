from __future__ import annotations

import sys

from greynoc_detector_engine.cli.main import app


def _normalize_args(argv: list[str]) -> list[str]:
    """Support the easy GreyNOC syntax: `gn - <command>`.

    The separator is optional, so `gn init` and `gn - init` both work.
    """
    if len(argv) > 1 and argv[1] == "-":
        return [argv[0], *argv[2:]]
    return argv


def main() -> None:
    sys.argv = _normalize_args(sys.argv)
    app()


if __name__ == "__main__":
    main()
