"""Agent expiry: the one place that decides whether an agent's ``expires_at`` has passed."""

from __future__ import annotations

from datetime import UTC, datetime


def agent_expired(expires_at: datetime | str | None, *, now: datetime | None = None) -> bool:
    """``True`` when ``expires_at`` is set and at or before ``now`` (default: the clock).

    ``None`` never expires. A naive value, or the ISO string SQLite hands back
    from a raw query, is read as UTC.
    """
    if expires_at is None:
        return False
    if isinstance(expires_at, str):
        expires_at = datetime.fromisoformat(expires_at)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    return expires_at <= (now or datetime.now(UTC))
