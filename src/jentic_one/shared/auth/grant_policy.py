"""A credential grant's policy: whether it has ended, when it will, and why.

A grant is the record that carries the policy: today the agent-to-credential
binding. This module is the one place that decides whether its policy has
ended, so the broker, the auth surface and the control plane agree on the
moment and on the reason they report (``expired_reason``).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from jentic_one.shared.auth.agent_expiry import as_utc


class GrantEndReason(StrEnum):
    """Which limit ended a grant, as binding responses and denials report it."""

    END_DATE = "end_date"
    """``expires_at`` has passed."""


@dataclass(frozen=True, slots=True)
class GrantPolicy:
    """The limits a grant carries; every field ``None`` means it never ends.

    Values may be naive datetimes or the ISO strings SQLite hands back from a
    raw query; both read as UTC.
    """

    expires_at: datetime | str | None = None

    @classmethod
    def from_row(cls, row: Any) -> GrantPolicy:
        """The policy columns of an ORM object or a SQL row (missing columns read as unset)."""
        return cls(expires_at=getattr(row, "expires_at", None))


def grant_deadline(policy: GrantPolicy) -> datetime | None:
    """The earliest moment a time-based limit ends the grant, or ``None``."""
    return as_utc(policy.expires_at) if policy.expires_at is not None else None


def grant_end_reason(policy: GrantPolicy, *, now: datetime | None = None) -> GrantEndReason | None:
    """Why the grant has ended as of ``now`` (default: the clock), or ``None`` while it holds."""
    now = now or datetime.now(UTC)
    if policy.expires_at is not None and as_utc(policy.expires_at) <= now:
        return GrantEndReason.END_DATE
    return None


def grant_ended(policy: GrantPolicy, *, now: datetime | None = None) -> bool:
    """Whether any limit of the grant has been reached as of ``now``."""
    return grant_end_reason(policy, now=now) is not None
