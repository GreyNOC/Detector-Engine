"""Shared API safety helpers (path containment, etc.)."""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import HTTPException

from greynoc_detector_engine.config.settings import Settings


def _allowed_roots(settings: Settings) -> list[Path]:
    roots = [settings.data_dir.resolve(), Path.cwd().resolve() / "data"]
    extra = os.environ.get("GREYNOC_FIXTURE_DIR")
    if extra:
        roots.append(Path(extra).resolve())
    # de-duplicate while preserving order
    seen: set[str] = set()
    out: list[Path] = []
    for r in roots:
        s = str(r)
        if s not in seen:
            seen.add(s)
            out.append(r)
    return out


def validate_fixture_path(value: str | None, settings: Settings) -> Path | None:
    """Resolve and confirm a fixture path lives inside an allowed root.

    Allowed roots:
      * ``settings.data_dir``
      * ``<cwd>/data``
      * ``$GREYNOC_FIXTURE_DIR`` if set

    Raises 400 on traversal attempts, missing files, or paths outside the
    allowlist. Returns ``None`` if the caller omitted the parameter.
    """
    if not value:
        return None
    candidate = Path(value)
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise HTTPException(status_code=400, detail=f"fixture not found: {value!r}") from exc

    for root in _allowed_roots(settings):
        try:
            resolved.relative_to(root)
            return resolved
        except ValueError:
            continue
    raise HTTPException(
        status_code=400,
        detail=(
            f"fixture path {value!r} is outside the allowed roots; "
            "set GREYNOC_FIXTURE_DIR to widen the allowlist if intentional."
        ),
    )
