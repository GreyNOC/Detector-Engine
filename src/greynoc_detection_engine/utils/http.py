from __future__ import annotations

from typing import Any

import httpx


class HttpFetchError(RuntimeError):
    pass


class DefensiveHttpClient:
    def __init__(self, timeout_seconds: float, user_agent: str) -> None:
        self.timeout_seconds = timeout_seconds
        self.user_agent = user_agent

    def get_json(self, url: str) -> Any:
        headers = {"User-Agent": self.user_agent, "Accept": "application/json"}
        try:
            with httpx.Client(timeout=self.timeout_seconds, follow_redirects=True) as client:
                response = client.get(url, headers=headers)
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as exc:
            raise HttpFetchError(f"failed to fetch JSON from {url}: {exc}") from exc

    def get_text(self, url: str) -> str:
        headers = {"User-Agent": self.user_agent}
        try:
            with httpx.Client(timeout=self.timeout_seconds, follow_redirects=True) as client:
                response = client.get(url, headers=headers)
                response.raise_for_status()
                return response.text
        except httpx.HTTPError as exc:
            raise HttpFetchError(f"failed to fetch text from {url}: {exc}") from exc
