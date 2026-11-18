"""Agent expiry: the one place that decides whether an agent's ``expires_at`` has passed."""

from __future__ import annotations

from datetime import UTC, datetime


def as_utc(value: datetime | str) -> datetime:
    """A timezone-aware datetime from a stored expiry.

    A naive value, or the ISO string SQLite hands back from a raw query, is
    read as UTC.
    """
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def agent_expired(expires_at: datetime | str | None, *, now: datetime | None = None) -> bool:
    """``True`` when ``expires_at`` is set and at or before ``now`` (default: the clock).

    ``None`` never expires. A naive value, or the ISO string SQLite hands back
    from a raw query, is read as UTC. Bindings use the same rule.
    """
    if expires_at is None:
        return False
    return as_utc(expires_at) <= (now or datetime.now(UTC))
