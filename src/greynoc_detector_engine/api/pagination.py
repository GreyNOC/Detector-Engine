from __future__ import annotations

from typing import Annotated, TypeAlias, TypeVar

from fastapi import Query

DEFAULT_LIMIT = 100
MAX_LIMIT = 500

LimitParam: TypeAlias = Annotated[int, Query(default=DEFAULT_LIMIT, ge=1, le=MAX_LIMIT)]

T = TypeVar("T")


def apply_limit(items: list[T], limit: int) -> list[T]:
    return items[:limit]
