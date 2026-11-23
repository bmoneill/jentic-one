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
