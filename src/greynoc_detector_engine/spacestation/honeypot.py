"""Tiny darknet TCP listener.

The listener binds an unused port, accepts inbound TCP, optionally captures
a bounded, sanitized preview of the first bytes the attacker sends, and
then closes the connection. We **never** write anything back to the remote,
so the listener cannot be coerced into amplifying, fingerprinting, or
speaking any application protocol.

Hardening (see docs/security_review.md):
  * Default bind is ``127.0.0.1``. A non-loopback bind requires the operator
    to set ``allow_external_bind=True`` so it cannot happen by accident.
  * Per-remote token-bucket rate limit prevents a single attacker from
    flooding the events table.
  * Payload preview is length-capped, control-character-stripped, and
    high-entropy tokens are redacted before storage.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import logging
import math
import re
import time
from collections import defaultdict
from collections.abc import Awaitable, Callable
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from greynoc_detector_engine.models.network import HoneypotEvent
from greynoc_detector_engine.utils.time import utc_now

EventSink = Callable[[HoneypotEvent], Awaitable[None] | None]

_LOG = logging.getLogger(__name__)

_HIGH_ENTROPY = re.compile(r"[A-Za-z0-9+/=_-]{16,}")
_PRINTABLE_FALLBACK = re.compile(r"[^\x20-\x7E]")


class HoneypotConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: str = "default-darknet"
    bind_host: str = "127.0.0.1"
    port: int = Field(ge=1, le=65535)
    capture_bytes: int = Field(default=64, ge=0, le=4096)
    read_timeout_seconds: float = Field(default=2.0, ge=0.1, le=10.0)
    max_concurrent: int = Field(default=50, ge=1, le=10_000)

    # New defaults — the previous behavior was "bind 0.0.0.0 by default".
    # We now require an explicit opt-in for any non-loopback bind.
    allow_external_bind: bool = False
    rate_limit_per_minute: int = Field(default=30, ge=1, le=10_000)
    payload_redact_high_entropy: bool = True


class _TokenBucket:
    """Simple per-source token-bucket rate limiter."""

    __slots__ = ("_buckets", "_capacity", "_refill_per_sec")

    def __init__(self, capacity_per_minute: int) -> None:
        self._capacity = capacity_per_minute
        self._refill_per_sec = capacity_per_minute / 60.0
        self._buckets: dict[str, tuple[float, float]] = defaultdict(
            lambda: (float(capacity_per_minute), time.monotonic())
        )

    def allow(self, key: str) -> bool:
        tokens, last = self._buckets[key]
        now = time.monotonic()
        tokens = min(self._capacity, tokens + (now - last) * self._refill_per_sec)
        if tokens < 1.0:
            self._buckets[key] = (tokens, now)
            return False
        self._buckets[key] = (tokens - 1.0, now)
        return True


class DarknetHoneypot:
    """Pure-asyncio TCP listener; emits HoneypotEvent per touch."""

    def __init__(
        self,
        config: HoneypotConfig,
        *,
        on_event: EventSink | None = None,
    ) -> None:
        self._validate_bind(config)
        self.config = config
        self._on_event = on_event
        self._server: asyncio.base_events.Server | None = None
        self._semaphore: asyncio.Semaphore | None = None
        self._bucket = _TokenBucket(config.rate_limit_per_minute)
        self.events: list[HoneypotEvent] = []
        self.dropped_due_to_rate_limit: int = 0

    async def start(self) -> None:
        if self._server is not None:
            return
        self._semaphore = asyncio.Semaphore(self.config.max_concurrent)
        self._server = await asyncio.start_server(
            self._handle, host=self.config.bind_host, port=self.config.port
        )
        _LOG.info(
            "darknet honeypot listening on %s:%d (label=%s, external=%s)",
            self.config.bind_host,
            self.config.port,
            self.config.label,
            self.config.allow_external_bind,
        )

    async def stop(self) -> None:
        if self._server is None:
            return
        self._server.close()
        await self._server.wait_closed()
        self._server = None

    async def serve_forever(self) -> None:
        await self.start()
        assert self._server is not None
        async with self._server:
            await self._server.serve_forever()

    async def _handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        assert self._semaphore is not None
        async with self._semaphore:
            peer = writer.get_extra_info("peername") or ("", 0)
            remote_address = str(peer[0]) if len(peer) >= 1 else ""
            remote_port = int(peer[1]) if len(peer) >= 2 else 0

            if not self._bucket.allow(remote_address or "_unknown_"):
                self.dropped_due_to_rate_limit += 1
                with contextlib.suppress(Exception):
                    writer.close()
                    await writer.wait_closed()
                return

            preview = ""
            bytes_received = 0
            if self.config.capture_bytes > 0:
                try:
                    raw = await asyncio.wait_for(
                        reader.read(self.config.capture_bytes),
                        timeout=self.config.read_timeout_seconds,
                    )
                    bytes_received = len(raw)
                    preview = self._sanitize_preview(raw)
                except (TimeoutError, ConnectionResetError, OSError):
                    pass
            event = HoneypotEvent(
                event_id=f"hp-{uuid4().hex[:12]}",
                listener_port=self.config.port,
                listener_label=self.config.label,
                remote_address=remote_address,
                remote_port=remote_port,
                payload_preview=preview or None,
                bytes_received=bytes_received,
                observed_at=utc_now(),
            )
            self.events.append(event)
            await self._dispatch(event)
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()

    async def _dispatch(self, event: HoneypotEvent) -> None:
        if self._on_event is None:
            return
        result = self._on_event(event)
        if asyncio.iscoroutine(result):
            await result

    # -- helpers -------------------------------------------------------------

    def _validate_bind(self, config: HoneypotConfig) -> None:
        host = config.bind_host
        if host in {"127.0.0.1", "::1", "localhost"}:
            return
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = None
        if ip is not None and ip.is_loopback:
            return
        if not config.allow_external_bind:
            raise ValueError(
                f"Honeypot bind {host!r} is not loopback. "
                "Set allow_external_bind=True to confirm you intend to expose "
                "this listener outside the local host."
            )

    def _sanitize_preview(self, raw: bytes) -> str:
        # Bounded printable preview.
        safe = bytearray()
        for byte in raw[: self.config.capture_bytes]:
            if 0x20 <= byte < 0x7F:
                safe.append(byte)
            else:
                safe.append(ord("."))
        text = safe.decode("ascii", errors="replace")
        if self.config.payload_redact_high_entropy:
            text = _HIGH_ENTROPY.sub(lambda m: f"[REDACTED:{_shannon(m.group(0)):.1f}b]", text)
        # Final fallback: strip anything still non-printable.
        return _PRINTABLE_FALLBACK.sub(".", text)


def _shannon(value: str) -> float:
    """Shannon entropy in bits; used only for the redaction tag."""
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())
