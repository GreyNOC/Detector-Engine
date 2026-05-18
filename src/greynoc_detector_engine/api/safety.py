"""Shared API safety helpers (path containment, etc.).

For ``fixture`` query parameters use the FastAPI dependency
``api.dependencies.resolve_fixture_path`` directly. This module covers the
non-dependency cases (e.g. ``asset_inventory`` on the prediction route).
"""

from __future__ import annotations

import contextlib
import os
from pathlib import Path

from fastapi import HTTPException

from greynoc_detector_engine.config.settings import Settings


def _allowed_roots(settings: Settings) -> list[Path]:
    """Return the directories under which path inputs are accepted."""
    roots: list[Path] = []
    with contextlib.suppress(OSError):
        roots.append(settings.fixture_root.resolve())
    with contextlib.suppress(OSError):
        roots.append(settings.data_dir.resolve())
    roots.append((Path.cwd() / "data").resolve())
    for env in ("GREYNOC_FIXTURE_ROOT", "GREYNOC_FIXTURE_DIR"):
        extra = os.environ.get(env)
        if extra:
            with contextlib.suppress(OSError):
                roots.append(Path(extra).resolve())

    seen: set[str] = set()
    out: list[Path] = []
    for r in roots:
        s = str(r)
        if s not in seen:
            seen.add(s)
            out.append(r)
    return out


def validate_fixture_path(value: str | None, settings: Settings) -> Path | None:
    """Resolve and confirm a fixture-style path lives inside an allowed root.

    Raises ``HTTPException(400)`` on traversal attempts, missing files, or
    paths outside the allowlist. Returns ``None`` if the caller omitted the
    parameter.
    """
    if not value:
        return None
    candidate = Path(value)
    if not candidate.is_absolute():
        # Resolve relative paths against the configured fixture root first.
        candidate = settings.fixture_root / candidate
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
            f"path {value!r} is outside the allowed roots; "
            "set GREYNOC_FIXTURE_ROOT or GREYNOC_FIXTURE_DIR to widen "
            "the allowlist if intentional."
        ),
    )
