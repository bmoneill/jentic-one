"""Durations an agent or operator types for how long access should last.

``"30m"``, ``"8h"``, ``"7d"`` (or a bare number of seconds) — the same fixed
units the console's duration control offers. There are deliberately no
months or years: their length depends on the calendar.
"""

from __future__ import annotations

import re

_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3_600, "d": 86_400}
_DURATION = re.compile(r"^\s*(\d+)\s*([smhd]?)\s*$")


def parse_duration_seconds(text: str) -> int:
    """Seconds in ``text`` (``"7d"``, ``"8h"``, ``"90m"``, ``"45s"`` or ``"3600"``).

    Raises :class:`ValueError` for anything else, or for zero.
    """
    match = _DURATION.match(text.lower())
    if match is None:
        raise ValueError(
            f"invalid duration {text!r}: use a whole number with s, m, h or d, for example 7d"
        )
    seconds = int(match.group(1)) * _UNIT_SECONDS[match.group(2) or "s"]
    if seconds <= 0:
        raise ValueError("a duration must be longer than zero")
    return seconds
