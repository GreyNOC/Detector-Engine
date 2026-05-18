from __future__ import annotations

import time
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlparse

import httpx


class HttpFetchError(RuntimeError):
    pass


class DefensiveHttpClient:
    def __init__(
        self,
        timeout_seconds: float,
        user_agent: str,
        *,
        retries: int = 2,
        max_response_bytes: int = 5_000_000,
        allowed_hosts: Iterable[str] | None = None,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.user_agent = user_agent
        self.retries = max(0, retries)
        self.max_response_bytes = max_response_bytes
        self.allowed_hosts = {host.lower() for host in allowed_hosts or []}

    def get_json(self, url: str) -> Any:
        headers = {"User-Agent": self.user_agent, "Accept": "application/json"}
        response = self._get(url, headers=headers)
        content_type = response.headers.get("content-type", "").lower()
        if "json" not in content_type and content_type:
            raise HttpFetchError(f"unexpected content type for JSON from {url}: {content_type}")
        try:
            return response.json()
        except ValueError as exc:
            raise HttpFetchError(f"failed to parse JSON from {url}: {exc}") from exc

    def get_text(self, url: str) -> str:
        headers = {"User-Agent": self.user_agent}
        return self._get(url, headers=headers).text

    def _get(self, url: str, *, headers: dict[str, str]) -> httpx.Response:
        self._validate_url(url)
        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            try:
                with httpx.Client(timeout=self.timeout_seconds, follow_redirects=True) as client:
                    response = client.get(url, headers=headers)
                    response.raise_for_status()
                    self._validate_response_size(url, response)
                    return response
            except httpx.HTTPError as exc:
                last_error = exc
                if attempt >= self.retries:
                    break
                time.sleep(min(2.0, 0.25 * (2**attempt)))
        raise HttpFetchError(f"failed to fetch {url}: {last_error}")

    def _validate_url(self, url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme not in {"https", "http"}:
            raise HttpFetchError(f"unsupported URL scheme for {url}")
        if not parsed.hostname:
            raise HttpFetchError(f"URL has no hostname: {url}")
        if self.allowed_hosts and parsed.hostname.lower() not in self.allowed_hosts:
            raise HttpFetchError(f"host is not in allowed_fetch_hosts: {parsed.hostname}")

    def _validate_response_size(self, url: str, response: httpx.Response) -> None:
        content_length = response.headers.get("content-length")
        if content_length and int(content_length) > self.max_response_bytes:
            raise HttpFetchError(f"response too large from {url}: {content_length} bytes")
        if len(response.content) > self.max_response_bytes:
            raise HttpFetchError(f"response too large from {url}: {len(response.content)} bytes")
