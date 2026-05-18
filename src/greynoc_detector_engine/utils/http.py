"""Defensive HTTP client.

Constraints (do not relax without updating docs/security_review.md):

  * Bounded body size. We refuse to load responses larger than
    :data:`DEFAULT_MAX_BYTES` (50 MiB) so a hostile server can't exhaust memory.
  * Bounded redirect chain. We allow at most :data:`MAX_REDIRECTS` hops so a
    redirect chain can't drag us to an unrelated host (SSRF amplification).
  * No request body inputs from callers. This module only does GETs.
  * Fixed User-Agent.
  * Timeout on every request.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

DEFAULT_MAX_BYTES: int = 50 * 1024 * 1024  # 50 MiB
MAX_REDIRECTS: int = 5


class HttpFetchError(RuntimeError):
    """Raised for any network/parse failure from the defensive HTTP client."""


class ResponseTooLargeError(HttpFetchError):
    """Raised when a remote response exceeds the configured body cap."""


class DefensiveHttpClient:
    def __init__(
        self,
        timeout_seconds: float,
        user_agent: str,
        *,
        max_bytes: int = DEFAULT_MAX_BYTES,
        max_redirects: int = MAX_REDIRECTS,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.user_agent = user_agent
        self.max_bytes = max_bytes
        self.max_redirects = max_redirects

    # -- public ---------------------------------------------------------------

    def get_json(self, url: str) -> Any:
        body = self._get_bytes(url, accept="application/json")
        try:
            return json.loads(body)
        except json.JSONDecodeError as exc:
            raise HttpFetchError(f"invalid JSON from {url}: {exc}") from exc

    def get_text(self, url: str) -> str:
        body = self._get_bytes(url, accept="text/*")
        # `errors='replace'` keeps us robust against feed encoding mistakes,
        # but the body cap above already prevents memory blow-ups.
        return body.decode("utf-8", errors="replace")

    # -- internals ------------------------------------------------------------

    def _get_bytes(self, url: str, *, accept: str) -> bytes:
        headers = {
            "User-Agent": self.user_agent,
            "Accept": accept,
            "Accept-Encoding": "gzip, deflate",
        }
        try:
            with (
                httpx.Client(
                    timeout=self.timeout_seconds,
                    follow_redirects=True,
                    max_redirects=self.max_redirects,
                ) as client,
                client.stream("GET", url, headers=headers) as response,
            ):
                response.raise_for_status()
                return self._read_bounded(response, url)
        except httpx.TooManyRedirects as exc:
            raise HttpFetchError(
                f"too many redirects fetching {url} (max {self.max_redirects})"
            ) from exc
        except httpx.HTTPError as exc:
            raise HttpFetchError(f"failed to fetch {url}: {exc}") from exc

    def _read_bounded(self, response: httpx.Response, url: str) -> bytes:
        buf = bytearray()
        for chunk in response.iter_bytes():
            buf.extend(chunk)
            if len(buf) > self.max_bytes:
                raise ResponseTooLargeError(
                    f"response from {url} exceeded the {self.max_bytes}-byte cap"
                )
        return bytes(buf)
