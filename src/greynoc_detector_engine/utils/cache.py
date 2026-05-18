"""On-disk HTTP response cache keyed by URL, with ETag/Last-Modified support.

We never re-download a feed unchanged. The cache stores response bytes plus
the validators the origin returned, so subsequent fetches can issue a
conditional ``If-None-Match`` / ``If-Modified-Since`` request. A 304 from
the origin means the cache stays valid.

Cache is stored under ``data/cache/`` by default; the directory is created
lazily and cache files are JSON envelopes that hold metadata + the body as
a UTF-8 string (we already cap response bytes upstream).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class CachedResponse:
    body: str
    etag: str | None
    last_modified: str | None
    fetched_at: str


class HttpResponseCache:
    """Tiny on-disk cache keyed by URL."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def conditional_headers(self, url: str) -> dict[str, str]:
        cached = self.get(url)
        if cached is None:
            return {}
        headers: dict[str, str] = {}
        if cached.etag:
            headers["If-None-Match"] = cached.etag
        if cached.last_modified:
            headers["If-Modified-Since"] = cached.last_modified
        return headers

    def get(self, url: str) -> CachedResponse | None:
        path = self._path_for(url)
        if not path.exists():
            return None
        try:
            payload: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return CachedResponse(
            body=str(payload.get("body", "")),
            etag=payload.get("etag"),
            last_modified=payload.get("last_modified"),
            fetched_at=str(payload.get("fetched_at", "")),
        )

    def put(
        self,
        url: str,
        body: str,
        *,
        etag: str | None,
        last_modified: str | None,
        fetched_at: str,
    ) -> None:
        path = self._path_for(url)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "url": url,
                    "body": body,
                    "etag": etag,
                    "last_modified": last_modified,
                    "fetched_at": fetched_at,
                },
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

    def _path_for(self, url: str) -> Path:
        key = hashlib.sha256(url.encode("utf-8")).hexdigest()[:24]
        return self.root / f"{key}.json"
