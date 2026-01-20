from __future__ import annotations

from datetime import datetime, timezone


def now_utc() -> datetime:
    """Return current UTC time as timezone-aware datetime."""
    return datetime.now(timezone.utc)


def fmt_iso(dt: datetime | None) -> str:
    """Format datetime as ISO 8601 string; handle None gracefully."""
    if dt is None:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()
