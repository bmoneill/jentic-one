"""The org's defaults and maximums for credential grants and agents (D7, step 8).

Every path that creates or renews a grant (binding a credential, renewing it,
confirming a connect request, deciding a ``grant_renewal`` hold), and every
path that sets an agent's expiry, runs the request through here, so the rule
lives in one place:

- **Defaults** apply only when a creation sets no policy at all (no end date,
  no idle limit and no use count): a request that sets any of them is taken
  as it is. The console always sets one, so it gets exactly what it chose.
- **Maximums** apply to the values a request sets: a request that leaves the
  end date alone (a renewal that only turns on the idle warning, say) is not
  refused because an older grant has none. A maximum also means every grant
  must have that limit, so "none" is refused too.

Limits are checked against the server's clock with a few minutes' grace: a
browser works the end date out from its own clock as the reviewer confirms,
so choosing exactly the maximum must not be refused for a few seconds' skew.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from jentic.problem_details import ProblemDetailException

from jentic_one.shared.auth.agent_expiry import as_utc
from jentic_one.shared.auth.grant_policy import UNSET, Unset
from jentic_one.shared.config.grant_expiry import GrantExpiryConfig

#: How far past a maximum an end date may land, for clock skew.
CLOCK_GRACE = timedelta(minutes=10)


class GrantPolicyLimitError(ProblemDetailException):
    """A grant or agent policy is outside the org's limits.

    A problem-details exception, so every surface answers it alike (422
    ``grant_policy_limit_exceeded``) through the app factory's central handler.
    """

    def __init__(self, detail: str, *, field: str) -> None:
        super().__init__(
            422,
            detail,
            type="grant_policy_limit_exceeded",
            title="Outside the org's access limits",
        )
        #: The problem's ``detail`` text (``detail`` itself is the whole problem body).
        self.message = detail
        self.field = field


def duration_label(seconds: int) -> str:
    """ "30 days", "12 hours", "45 minutes", "90 seconds"."""
    for unit, size in (("day", 86_400), ("hour", 3_600), ("minute", 60)):
        if seconds % size == 0:
            n = seconds // size
            return f"{n} {unit}{'' if n == 1 else 's'}"
    return f"{seconds} second{'' if seconds == 1 else 's'}"


@dataclass(frozen=True, slots=True)
class NewGrantPolicy:
    """A new grant's policy after the org's defaults."""

    expires_at: datetime | None
    max_idle_period: int | None
    max_quota: int | None


def _check_end(
    expires_at: datetime | None, maximum: int | None, *, now: datetime, field: str, what: str
) -> None:
    if maximum is None:
        return
    label = duration_label(maximum)
    if expires_at is None:
        raise GrantPolicyLimitError(
            f"This org requires every {what} to end within {label}: set an end date",
            field=field,
        )
    if as_utc(expires_at) > now + timedelta(seconds=maximum) + CLOCK_GRACE:
        raise GrantPolicyLimitError(
            f"This org allows a {what} to last at most {label}: choose an earlier end date",
            field=field,
        )


def check_grant_limits(
    config: GrantExpiryConfig,
    *,
    now: datetime,
    expires_at: datetime | Unset | None = UNSET,
    max_idle_period: int | Unset | None = UNSET,
) -> None:
    """Refuse a grant policy a request sets beyond the org's maximums.

    Only the fields a request sets are checked (``UNSET`` is left alone).
    """
    if not isinstance(expires_at, Unset):
        _check_end(expires_at, config.max_expires_in_s, now=now, field="expires_at", what="grant")
    if not isinstance(max_idle_period, Unset) and config.max_idle_period_s is not None:
        label = duration_label(config.max_idle_period_s)
        if max_idle_period is None:
            raise GrantPolicyLimitError(
                f"This org requires every grant to have an idle limit of at most {label}",
                field="max_idle_period",
            )
        if max_idle_period > config.max_idle_period_s:
            raise GrantPolicyLimitError(
                f"This org allows an idle limit of at most {label}", field="max_idle_period"
            )


def new_grant_policy(
    config: GrantExpiryConfig,
    *,
    now: datetime,
    expires_at: datetime | Unset | None = UNSET,
    max_idle_period: int | Unset | None = UNSET,
    max_quota: int | Unset | None = UNSET,
) -> NewGrantPolicy:
    """A new grant's policy: the org's default when the request sets none, then its maximums.

    The default end date is the configured default lifetime, or the maximum
    when only a maximum is set (every grant must then end).
    """
    if all(isinstance(v, Unset) for v in (expires_at, max_idle_period, max_quota)):
        lifetime = config.default_expires_in_s or config.max_expires_in_s
        policy = NewGrantPolicy(
            expires_at=now + timedelta(seconds=lifetime) if lifetime else None,
            max_idle_period=config.default_idle_period_s or config.max_idle_period_s,
            max_quota=1 if config.single_use_by_default else None,
        )
    else:
        policy = NewGrantPolicy(
            expires_at=None if isinstance(expires_at, Unset) else expires_at,
            max_idle_period=None if isinstance(max_idle_period, Unset) else max_idle_period,
            max_quota=None if isinstance(max_quota, Unset) else max_quota,
        )
    check_grant_limits(
        config, now=now, expires_at=policy.expires_at, max_idle_period=policy.max_idle_period
    )
    return policy


def check_agent_expiry(
    config: GrantExpiryConfig, *, now: datetime, expires_at: datetime | None
) -> None:
    """Refuse an agent expiry a request sets beyond the org's maximum."""
    _check_end(expires_at, config.agent_max_expires_in_s, now=now, field="expires_at", what="agent")


def default_agent_expiry(config: GrantExpiryConfig, *, now: datetime) -> datetime | None:
    """The expiry of an agent created or approved without one: the default, else the maximum."""
    lifetime = config.agent_default_expires_in_s or config.agent_max_expires_in_s
    return now + timedelta(seconds=lifetime) if lifetime else None
