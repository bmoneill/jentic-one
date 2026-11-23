"""The org's defaults and maximums for grants and agents (step 8)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from jentic_one.shared.auth.grant_limits import (
    CLOCK_GRACE,
    GrantPolicyLimitError,
    check_agent_expiry,
    check_grant_limits,
    default_agent_expiry,
    duration_label,
    new_grant_policy,
)
from jentic_one.shared.config import GrantExpiryConfig

NOW = datetime(2026, 11, 23, 12, 0, tzinfo=UTC)
DAY = 86_400


def test_open_source_defaults_change_nothing() -> None:
    policy = new_grant_policy(GrantExpiryConfig(), now=NOW)
    assert (policy.expires_at, policy.max_idle_period, policy.max_quota) == (None, None, None)
    check_grant_limits(GrantExpiryConfig(), now=NOW, expires_at=None, max_idle_period=None)


def test_a_creation_that_sets_no_policy_gets_the_default() -> None:
    config = GrantExpiryConfig(
        default_expires_in_s=7 * DAY, default_idle_period_s=14 * DAY, single_use_by_default=True
    )
    policy = new_grant_policy(config, now=NOW)
    assert policy.expires_at == NOW + timedelta(days=7)
    assert policy.max_idle_period == 14 * DAY
    assert policy.max_quota == 1


def test_a_creation_that_sets_any_limit_is_taken_as_it_is() -> None:
    config = GrantExpiryConfig(default_expires_in_s=7 * DAY, default_idle_period_s=14 * DAY)
    policy = new_grant_policy(config, now=NOW, max_quota=1)
    assert (policy.expires_at, policy.max_idle_period, policy.max_quota) == (None, None, 1)


def test_a_maximum_alone_is_the_default_and_every_grant_must_end() -> None:
    config = GrantExpiryConfig(max_expires_in_s=30 * DAY)
    assert new_grant_policy(config, now=NOW).expires_at == NOW + timedelta(days=30)
    with pytest.raises(GrantPolicyLimitError) as none:
        new_grant_policy(config, now=NOW, expires_at=None)
    assert none.value.field == "expires_at"
    assert none.value.status_code == 422
    assert "within 30 days" in none.value.message
    with pytest.raises(GrantPolicyLimitError, match="at most 30 days"):
        check_grant_limits(config, now=NOW, expires_at=NOW + timedelta(days=31))
    # The maximum itself passes, with grace for a browser's clock.
    check_grant_limits(config, now=NOW, expires_at=NOW + timedelta(days=30) + CLOCK_GRACE)


def test_a_maximum_only_checks_what_a_renewal_sets() -> None:
    config = GrantExpiryConfig(max_expires_in_s=30 * DAY, max_idle_period_s=14 * DAY)
    # Turning on the idle warning alone leaves an older grant's lack of an end date alone.
    check_grant_limits(config, now=NOW)
    with pytest.raises(GrantPolicyLimitError, match="idle limit of at most 14 days"):
        check_grant_limits(config, now=NOW, max_idle_period=None)
    with pytest.raises(GrantPolicyLimitError, match="at most 14 days"):
        check_grant_limits(config, now=NOW, max_idle_period=30 * DAY)


def test_agent_expiry_default_and_maximum() -> None:
    assert default_agent_expiry(GrantExpiryConfig(), now=NOW) is None
    config = GrantExpiryConfig(agent_default_expires_in_s=DAY, agent_max_expires_in_s=7 * DAY)
    assert default_agent_expiry(config, now=NOW) == NOW + timedelta(days=1)
    check_agent_expiry(config, now=NOW, expires_at=NOW + timedelta(days=7))
    with pytest.raises(GrantPolicyLimitError, match="every agent"):
        check_agent_expiry(config, now=NOW, expires_at=None)


def test_a_default_above_its_maximum_is_a_config_error() -> None:
    with pytest.raises(ValueError, match="must not exceed"):
        GrantExpiryConfig(default_expires_in_s=31 * DAY, max_expires_in_s=30 * DAY)


@pytest.mark.parametrize(
    ("seconds", "label"),
    [
        (DAY, "1 day"),
        (30 * DAY, "30 days"),
        (7_200, "2 hours"),
        (60, "1 minute"),
        (90, "90 seconds"),
    ],
)
def test_duration_label(seconds: int, label: str) -> None:
    assert duration_label(seconds) == label
