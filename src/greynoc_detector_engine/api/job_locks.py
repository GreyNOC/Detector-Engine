from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager

from fastapi import HTTPException, status

_RUNNING_JOBS: set[str] = set()
_LOCK = threading.Lock()


@contextmanager
def single_running_job(job_key: str) -> Iterator[None]:
    with _LOCK:
        if job_key in _RUNNING_JOBS:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Job already running: {job_key}",
            )
        _RUNNING_JOBS.add(job_key)
    try:
        yield
    finally:
        with _LOCK:
            _RUNNING_JOBS.discard(job_key)
