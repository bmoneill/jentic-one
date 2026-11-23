"""A credential grant's policy: whether it has ended, when it will, and why.

A grant is the record that carries the policy: today the agent-to-credential
binding. It can carry any combination of limits, and it ends as soon as **any**
of them is reached:

- an end date (``expires_at``);
- an idle limit (``max_idle_period``, whole seconds): the grant ends once it
  has gone that long without a use. The idle clock runs from the later of the
  last use (``last_used_at``) and the last grant or renewal (``renewed_at``,
  falling back to ``bound_at``), so a grant that is never used ends one idle
  period after it was granted, and a renewal restarts the clock without
  counting as a use.

This module is the one place that decides it, so the broker, the auth surface
and the control plane agree on the moment and on the reason they report
(``expired_reason``).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum, StrEnum
from typing import Any

from jentic_one.shared.auth.agent_expiry import as_utc

#: The shortest idle limit a grant may carry: ``last_used_at`` is written only
#: about once an hour, so shorter limits could not be honoured exactly.
MIN_IDLE_PERIOD_SECONDS = 86_400

#: The longest idle limit (999 days, the console's largest custom amount).
MAX_IDLE_PERIOD_SECONDS = 999 * 86_400

#: SQL column list a raw query selects to build a :class:`GrantPolicy`.
GRANT_POLICY_COLUMNS = "expires_at, max_idle_period, last_used_at, renewed_at, bound_at"


class Unset(Enum):
    """A policy field a change leaves alone, as opposed to ``None``, which clears it."""

    TOKEN = 0


UNSET = Unset.TOKEN

#: The binding columns that make up its policy, as audits record them.
GRANT_POLICY_FIELDS = ("expires_at", "max_idle_period")


class GrantEndReason(StrEnum):
    """Which limit ended a grant, as binding responses and denials report it."""

    END_DATE = "end_date"
    """``expires_at`` has passed."""
    IDLE = "idle"
    """It went ``max_idle_period`` without a use."""


@dataclass(frozen=True, slots=True)
class GrantPolicy:
    """The limits a grant carries and the clock they run against.

    Every limit ``None`` means the grant never ends. Datetimes may be naive or
    the ISO strings SQLite hands back from a raw query; both read as UTC.
    """

    expires_at: datetime | str | None = None
    max_idle_period: int | None = None
    last_used_at: datetime | str | None = None
    renewed_at: datetime | str | None = None
    bound_at: datetime | str | None = None

    @classmethod
    def from_row(cls, row: Any) -> GrantPolicy:
        """The policy columns of an ORM object or a SQL row (missing columns read as unset)."""
        return cls(
            expires_at=getattr(row, "expires_at", None),
            max_idle_period=getattr(row, "max_idle_period", None),
            last_used_at=getattr(row, "last_used_at", None),
            renewed_at=getattr(row, "renewed_at", None),
            bound_at=getattr(row, "bound_at", None),
        )


def _utc(value: datetime | str | None) -> datetime | None:
    return as_utc(value) if value is not None else None


def idle_clock_start(policy: GrantPolicy) -> datetime | None:
    """When the idle clock last restarted: the later of the last use and the last renewal."""
    starts = [
        start
        for start in (_utc(policy.last_used_at), _utc(policy.renewed_at) or _utc(policy.bound_at))
        if start is not None
    ]
    return max(starts, default=None)


def idle_deadline(policy: GrantPolicy) -> datetime | None:
    """When the idle limit ends the grant if it goes unused, or ``None`` without one."""
    if policy.max_idle_period is None:
        return None
    start = idle_clock_start(policy)
    return start + timedelta(seconds=policy.max_idle_period) if start is not None else None


def grant_deadline(policy: GrantPolicy) -> datetime | None:
    """The earliest moment a time-based limit ends the grant, or ``None``."""
    deadlines = [d for d in (_utc(policy.expires_at), idle_deadline(policy)) if d is not None]
    return min(deadlines, default=None)


def grant_end_reason(policy: GrantPolicy, *, now: datetime | None = None) -> GrantEndReason | None:
    """Why the grant has ended as of ``now`` (default: the clock), or ``None`` while it holds.

    When several limits have been reached, the one reached first is reported.
    """
    now = now or datetime.now(UTC)
    reached = [
        (deadline, reason)
        for deadline, reason in (
            (_utc(policy.expires_at), GrantEndReason.END_DATE),
            (idle_deadline(policy), GrantEndReason.IDLE),
        )
        if deadline is not None and deadline <= now
    ]
    return min(reached, key=lambda pair: pair[0])[1] if reached else None


def grant_ended(policy: GrantPolicy, *, now: datetime | None = None) -> bool:
    """Whether any limit of the grant has been reached as of ``now``."""
    return grant_end_reason(policy, now=now) is not None
