"""Tiny time helpers. SQLite returns DateTime columns as naive Python datetimes,
while Postgres returns them tz-aware. `aware()` normalizes everything to UTC
so comparisons against `now()` always work."""

from datetime import datetime, timezone


def now() -> datetime:
    return datetime.now(tz=timezone.utc)


def aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
