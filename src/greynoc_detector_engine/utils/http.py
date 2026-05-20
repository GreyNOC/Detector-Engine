"""Defensive HTTP client.

Constraints (do not relax without updating docs/security_review.md):

  * Bounded body size. We refuse to load responses larger than
    ``max_response_bytes`` (defaults to 5,000,000 bytes) so a hostile server
    can't exhaust memory; the limit is enforced *streaming*, not after read.
  * Bounded redirect chain. We allow at most :data:`MAX_REDIRECTS` hops so a
    redirect chain can't drag us to an unrelated host (SSRF amplification).
  * Host allowlist. When ``allowed_hosts`` is non-empty, only those hosts
    can be fetched. Public engine builds leave this empty; private builds
    can lock it down.
  * Content-type sanity. JSON fetches that come back as something else are
    rejected.
  * Retries with exponential backoff for transient failures.
  * No request body inputs from callers. This module only does GETs.
  * Fixed User-Agent.
  * Timeout on every request.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterable
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

DEFAULT_MAX_BYTES: int = 5_000_000
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
        retries: int = 2,
        max_response_bytes: int = DEFAULT_MAX_BYTES,
        max_redirects: int = MAX_REDIRECTS,
        allowed_hosts: Iterable[str] | None = None,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.user_agent = user_agent
        self.retries = max(0, retries)
        self.max_response_bytes = max_response_bytes
        self.max_redirects = max_redirects
        self.allowed_hosts: set[str] = {host.lower() for host in allowed_hosts or []}

    # -- public ---------------------------------------------------------------

    def get_json(self, url: str) -> Any:
        body, content_type = self._get_bytes(url, accept="application/json")
        if content_type and "json" not in content_type:
            raise HttpFetchError(f"unexpected content type for JSON from {url}: {content_type}")
        try:
            return json.loads(body)
        except json.JSONDecodeError as exc:
            raise HttpFetchError(f"invalid JSON from {url}: {exc}") from exc

    def get_text(self, url: str) -> str:
        body, _ = self._get_bytes(url, accept="text/*")
        # ``errors='replace'`` keeps us robust against feed encoding mistakes;
        # the body cap above already prevents memory blow-ups.
        return body.decode("utf-8", errors="replace")

    # -- internals ------------------------------------------------------------

    def _get_bytes(self, url: str, *, accept: str) -> tuple[bytes, str]:
        self._validate_url(url)
        headers = {
            "User-Agent": self.user_agent,
            "Accept": accept,
            "Accept-Encoding": "gzip, deflate",
        }
        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            current_url = url
            try:
                with httpx.Client(
                    timeout=self.timeout_seconds,
                    follow_redirects=False,
                ) as client:
                    for redirect_count in range(self.max_redirects + 1):
                        with client.stream("GET", current_url, headers=headers) as response:
                            if response.is_redirect:
                                if redirect_count >= self.max_redirects:
                                    raise HttpFetchError(
                                        f"too many redirects fetching {url} "
                                        f"(max {self.max_redirects})"
                                    )
                                current_url = self._resolve_redirect_url(
                                    current_url,
                                    response.headers.get("location"),
                                    original_url=url,
                                )
                                continue

                            response.raise_for_status()
                            self._validate_content_length(current_url, response)
                            body = self._read_bounded(response, current_url)
                            return body, response.headers.get("content-type", "").lower()
            except (ResponseTooLargeError, HttpFetchError):
                raise
            except httpx.HTTPError as exc:
                last_error = exc
                if attempt >= self.retries:
                    break
                time.sleep(min(2.0, 0.25 * (2**attempt)))
        raise HttpFetchError(f"failed to fetch {url}: {last_error}")

    def _resolve_redirect_url(
        self,
        current_url: str,
        location: str | None,
        *,
        original_url: str,
    ) -> str:
        if not location:
            raise HttpFetchError(f"redirect from {current_url} did not include a Location header")

        next_url = urljoin(current_url, location)
        self._validate_url(next_url)

        if not self.allowed_hosts:
            original_host = urlparse(original_url).hostname or ""
            next_host = urlparse(next_url).hostname or ""
            if next_host.lower() != original_host.lower():
                raise HttpFetchError(f"cross-host redirect refused: {original_host} -> {next_host}")
        return next_url

    def _read_bounded(self, response: httpx.Response, url: str) -> bytes:
        buf = bytearray()
        for chunk in response.iter_bytes():
            buf.extend(chunk)
            if len(buf) > self.max_response_bytes:
                raise ResponseTooLargeError(
                    f"response from {url} exceeded the {self.max_response_bytes}-byte cap"
                )
        return bytes(buf)

    def _validate_url(self, url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme not in {"https", "http"}:
            raise HttpFetchError(f"unsupported URL scheme for {url}")
        if not parsed.hostname:
            raise HttpFetchError(f"URL has no hostname: {url}")
        if self.allowed_hosts and parsed.hostname.lower() not in self.allowed_hosts:
            raise HttpFetchError(f"host is not in allowed_fetch_hosts: {parsed.hostname}")

    def _validate_content_length(self, url: str, response: httpx.Response) -> None:
        content_length = response.headers.get("content-length")
        if content_length is None:
            return
        try:
            declared = int(content_length)
        except ValueError:
            return
        if declared > self.max_response_bytes:
            raise ResponseTooLargeError(
                f"response too large from {url}: declared {declared} bytes "
                f"(cap {self.max_response_bytes})"
            )
