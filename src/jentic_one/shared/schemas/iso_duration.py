"""ISO 8601 durations on the wire for a binding's idle limit (``max_idle_period``).

The API carries an idle limit as an ISO 8601 duration string (``"P14D"``,
``"PT36H"``, ``"P2W"``, ``"P1DT12H"``); storage and every layer below the
schemas keep whole seconds. Only fixed-length units are accepted — weeks,
days, hours, minutes and seconds — never years or months, whose length
depends on the calendar.

- :data:`IdlePeriodRequest` is a request field: it accepts only a duration
  string (a bare number is refused) and checks the idle-limit range.
- :data:`IdlePeriodResponse` is a response field: built from seconds (or its
  own rendered string, so a response can be rebuilt from another's dump), it
  renders as the shortest duration string (``1_209_600`` → ``"P14D"``).
"""

from __future__ import annotations

import re
from typing import Annotated, Any

from pydantic import AfterValidator, BeforeValidator, PlainSerializer, WithJsonSchema

from jentic_one.shared.auth.grant_policy import MAX_IDLE_PERIOD_SECONDS, MIN_IDLE_PERIOD_SECONDS

_DAY = 86_400
_DURATION = re.compile(
    r"^P(?:(?P<w>\d+)W)?(?:(?P<d>\d+)D)?"
    r"(?:T(?=\d)(?:(?P<h>\d+)H)?(?:(?P<m>\d+)M)?(?:(?P<s>\d+)S)?)?$"
)
_UNIT_SECONDS = {"w": 7 * _DAY, "d": _DAY, "h": 3_600, "m": 60, "s": 1}


def parse_iso_duration(text: str) -> int:
    """Whole seconds in an ISO 8601 duration (``"P14D"``, ``"PT36H"``, ``"P1DT12H"``).

    Raises :class:`ValueError` for anything else: an empty duration (``"P"``),
    fractions, or years and months (``"P1M"``, ``"P1Y"``).
    """
    match = _DURATION.match(text.strip().upper())
    if match is None or not any(match.groupdict().values()):
        raise ValueError(
            f"invalid ISO 8601 duration {text!r}: use weeks, days, hours, minutes or seconds,"
            " for example P14D or PT36H (no years or months)"
        )
    return sum(int(v) * _UNIT_SECONDS[k] for k, v in match.groupdict().items() if v)


def format_iso_duration(seconds: int) -> str:
    """The shortest ISO 8601 duration for ``seconds`` (``1_209_600`` → ``"P14D"``)."""
    days, rest = divmod(int(seconds), _DAY)
    hours, rest = divmod(rest, 3_600)
    minutes, secs = divmod(rest, 60)
    time = "".join(f"{n}{u}" for n, u in ((hours, "H"), (minutes, "M"), (secs, "S")) if n)
    if not days and not time:
        return "PT0S"
    return f"P{f'{days}D' if days else ''}{f'T{time}' if time else ''}"


def _parse_request(value: Any) -> int:
    if not isinstance(value, str):
        raise ValueError("must be an ISO 8601 duration string, for example P14D")
    return parse_iso_duration(value)


def _parse_response(value: Any) -> Any:
    return parse_iso_duration(value) if isinstance(value, str) else value


def _check_idle_range(seconds: int) -> int:
    if not MIN_IDLE_PERIOD_SECONDS <= seconds <= MAX_IDLE_PERIOD_SECONDS:
        raise ValueError("an idle limit must be between 1 day (P1D) and 999 days (P999D)")
    return seconds


_JSON_SCHEMA = {"type": "string", "format": "duration", "examples": ["P14D"]}

#: A request's idle limit: an ISO 8601 duration string, 1 to 999 days.
IdlePeriodRequest = Annotated[
    int,
    BeforeValidator(_parse_request),
    AfterValidator(_check_idle_range),
    PlainSerializer(format_iso_duration, return_type=str, when_used="json"),
    WithJsonSchema(_JSON_SCHEMA),
]

#: A response's idle limit: seconds in, an ISO 8601 duration string out.
IdlePeriodResponse = Annotated[
    int,
    BeforeValidator(_parse_response),
    PlainSerializer(format_iso_duration, return_type=str, when_used="json"),
    WithJsonSchema(_JSON_SCHEMA),
]
