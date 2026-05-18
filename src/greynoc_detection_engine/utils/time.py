from __future__ import annotations

from datetime import UTC, date, datetime, time


def utc_now() -> datetime:
    return datetime.now(UTC)


def ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def parse_datetime(value: str | datetime | date | None) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return ensure_utc(value)
    if isinstance(value, date):
        return datetime.combine(value, time.min, tzinfo=UTC)
    normalized = value.strip()
    if not normalized:
        return None
    normalized = normalized.replace("Z", "+00:00")
    try:
        return ensure_utc(datetime.fromisoformat(normalized))
    except ValueError:
        parsed_date = date.fromisoformat(normalized)
        return datetime.combine(parsed_date, time.min, tzinfo=UTC)


def parse_date(value: str | date | datetime | None) -> date | None:
    parsed = parse_datetime(value)
    return parsed.date() if parsed else None
