"""Tests for the shared grant-policy evaluation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from jentic_one.shared.auth.grant_policy import (
    GrantEndReason,
    GrantPolicy,
    grant_deadline,
    grant_end_reason,
    grant_ended,
)

NOW = datetime(2026, 11, 23, 12, 0, tzinfo=UTC)


def test_no_policy_never_ends() -> None:
    assert grant_end_reason(GrantPolicy(), now=NOW) is None
    assert grant_deadline(GrantPolicy()) is None


def test_end_date_before_at_and_after_now() -> None:
    assert grant_end_reason(GrantPolicy(expires_at=NOW + timedelta(seconds=1)), now=NOW) is None
    assert grant_end_reason(GrantPolicy(expires_at=NOW), now=NOW) is GrantEndReason.END_DATE
    assert grant_ended(GrantPolicy(expires_at=NOW - timedelta(days=1)), now=NOW)


def test_sqlite_strings_read_as_utc() -> None:
    policy = GrantPolicy(expires_at="2026-11-23 11:59:00")
    assert grant_end_reason(policy, now=NOW) is GrantEndReason.END_DATE
    assert grant_deadline(policy) == NOW - timedelta(minutes=1)


def test_from_row_reads_missing_columns_as_unset() -> None:
    class Row:
        expires_at = NOW

    assert GrantPolicy.from_row(Row()) == GrantPolicy(expires_at=NOW)
    assert GrantPolicy.from_row(object()) == GrantPolicy()


DAY = timedelta(days=1)


def test_idle_limit_runs_from_the_last_use() -> None:
    policy = GrantPolicy(
        max_idle_period=14 * 86_400,
        last_used_at=NOW - 13 * DAY,
        renewed_at=NOW - 30 * DAY,
    )
    assert grant_end_reason(policy, now=NOW) is None
    assert grant_deadline(policy) == NOW + DAY
    assert grant_end_reason(policy, now=NOW + DAY) is GrantEndReason.IDLE


def test_a_never_used_grant_ends_one_idle_period_after_it_was_granted() -> None:
    policy = GrantPolicy(max_idle_period=7 * 86_400, bound_at=NOW - 7 * DAY)
    assert grant_end_reason(policy, now=NOW) is GrantEndReason.IDLE
    assert grant_end_reason(policy, now=NOW - timedelta(seconds=1)) is None


def test_a_renewal_restarts_the_idle_clock_without_a_use() -> None:
    policy = GrantPolicy(
        max_idle_period=7 * 86_400,
        last_used_at=NOW - 20 * DAY,
        renewed_at=NOW - DAY,
        bound_at=NOW - 60 * DAY,
    )
    assert grant_end_reason(policy, now=NOW) is None
    assert grant_deadline(policy) == NOW + 6 * DAY


def test_any_limit_ends_the_grant_and_the_first_reached_is_reported() -> None:
    # The end date passes while the grant is still in use.
    in_use = GrantPolicy(
        expires_at=NOW - DAY, max_idle_period=7 * 86_400, last_used_at=NOW - timedelta(hours=1)
    )
    assert grant_end_reason(in_use, now=NOW) is GrantEndReason.END_DATE
    # The grant goes unused before its end date.
    unused = GrantPolicy(
        expires_at=NOW + 30 * DAY, max_idle_period=7 * 86_400, last_used_at=NOW - 8 * DAY
    )
    assert grant_end_reason(unused, now=NOW) is GrantEndReason.IDLE
    # Both reached: the idle limit ran out first.
    both = GrantPolicy(expires_at=NOW - DAY, max_idle_period=86_400, last_used_at=NOW - 5 * DAY)
    assert grant_end_reason(both, now=NOW) is GrantEndReason.IDLE
    assert grant_deadline(both) == NOW - 4 * DAY
