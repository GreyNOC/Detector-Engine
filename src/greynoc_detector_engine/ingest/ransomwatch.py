from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from greynoc_detector_engine.ingest.base import BaseIngestor
from greynoc_detector_engine.utils.time import parse_datetime, utc_now


class RansomwatchPost(BaseModel):
    """Public ransomware-leak-site post observation, metadata only."""

    model_config = ConfigDict(extra="forbid")

    actor: str
    victim: str | None = None
    sector: str | None = None
    country: str | None = None
    posted_at: datetime = Field(default_factory=utc_now)
    description: str | None = None
    source: str = "Ransomwatch"


class RansomwatchIngestor(BaseIngestor[RansomwatchPost]):
    """Ingest public ransomware-leak-site metadata (e.g., ransomwatch.telemetry.ltd).

    Strictly metadata-only: we record *that* an actor claimed a victim, never
    download leaked material. This is one of the strongest forward-looking
    signals — actors usually claim victims days before public discovery, and
    sector trends reveal which industries the actor is currently hunting.
    """

    def ingest(self) -> list[RansomwatchPost]:
        payload = self.load_json_payload()
        rows = self._iter_rows(payload)
        return [self._normalize(row) for row in rows if self._has_actor(row)]

    @staticmethod
    def _has_actor(row: dict[str, Any]) -> bool:
        return bool(row.get("group_name") or row.get("group") or row.get("actor"))

    @staticmethod
    def _iter_rows(payload: Any) -> list[dict[str, Any]]:
        if isinstance(payload, list):
            return [r for r in payload if isinstance(r, dict)]
        if isinstance(payload, dict) and isinstance(payload.get("posts"), list):
            return [r for r in payload["posts"] if isinstance(r, dict)]
        if isinstance(payload, dict) and isinstance(payload.get("data"), list):
            return [r for r in payload["data"] if isinstance(r, dict)]
        return []

    @staticmethod
    def _normalize(row: dict[str, Any]) -> RansomwatchPost:
        actor_raw = row.get("group_name") or row.get("group") or row.get("actor") or "unknown"
        return RansomwatchPost(
            actor=str(actor_raw).lower(),
            victim=row.get("post_title") or row.get("victim"),
            sector=row.get("sector") or row.get("industry"),
            country=row.get("country"),
            posted_at=parse_datetime(
                row.get("discovered") or row.get("published") or row.get("posted_at")
            )
            or utc_now(),
            description=row.get("description") or row.get("notes"),
        )
