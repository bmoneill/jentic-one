"""Credential grant expiry: how agents' bindings to credentials end.

The owner's opt-in warning before a binding's idle limit is reached is set
here. The limits themselves live on each binding and are enforced by the
broker when it reads the binding; nothing here enforces them.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class GrantExpiryConfig(BaseModel):
    """Settings for credential grant (agent binding) expiry."""

    idle_warning_interval_s: int = Field(
        default=86_400,
        ge=60,
        description=(
            "Seconds between runs of the job that warns an agent's owner before a "
            "binding with the idle warning on reaches its idle limit. Defaults to once a "
            "day; the warning window should be at least twice this, so every binding is "
            "seen at least once inside it."
        ),
    )
    idle_warning_window_h: int = Field(
        default=48,
        ge=1,
        description=(
            "Hours before a binding's idle deadline within which its owner is warned "
            "(once per idle period). Defaults to 48."
        ),
    )
    idle_warning_min_idle_days: int = Field(
        default=4,
        ge=1,
        description=(
            "Shortest idle limit, in days, that is ever warned about. Below this a warning "
            "would cover half the idle window or more and arrive for bindings doing exactly "
            "what they were set up to do. Defaults to 4."
        ),
    )
