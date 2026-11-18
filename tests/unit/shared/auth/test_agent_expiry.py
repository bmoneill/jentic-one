"""Tests for the shared agent-expiry check."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from jentic_one.shared.auth.agent_expiry import agent_expired

NOW = datetime(2026, 11, 18, 12, 0, tzinfo=UTC)


def test_no_expiry_never_expires() -> None:
    assert agent_expired(None, now=NOW) is False


def test_future_is_not_expired() -> None:
    assert agent_expired(NOW + timedelta(seconds=1), now=NOW) is False


def test_exactly_now_is_expired() -> None:
    assert agent_expired(NOW, now=NOW) is True


def test_past_is_expired() -> None:
    assert agent_expired(NOW - timedelta(hours=1), now=NOW) is True


def test_naive_datetime_reads_as_utc() -> None:
    assert agent_expired(NOW.replace(tzinfo=None) - timedelta(minutes=1), now=NOW) is True


def test_iso_string_from_sqlite_is_parsed() -> None:
    assert agent_expired("2026-11-18 11:59:00", now=NOW) is True
    assert agent_expired("2026-11-18 12:01:00", now=NOW) is False
