"""Unit tests for credential secret previews (``secret_preview``)."""

from __future__ import annotations

from jentic_one.shared.redaction import secret_preview


def test_preview_normal_token() -> None:
    assert secret_preview("sk-1234567890abcdef") == "…def"


def test_preview_short_token_masked() -> None:
    assert secret_preview("ab") == "…***"


def test_preview_exactly_three_chars_masked() -> None:
    assert secret_preview("abc") == "…***"


def test_preview_four_chars_shows_last_three() -> None:
    assert secret_preview("abcd") == "…bcd"


def test_preview_empty_string_masked() -> None:
    assert secret_preview("") == "…***"
