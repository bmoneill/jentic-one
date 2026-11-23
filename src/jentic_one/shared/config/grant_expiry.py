"""Credential grant expiry: how agents' bindings to credentials end.

The limits themselves live on each binding and are enforced by the broker when
it reads the binding. Set here, deployment-wide (one org per deployment):

- the org's defaults and maximums for new grants (D7, step 8): a default
  applies when a request to create a grant sets no policy at all; a maximum
  refuses (422) anything longer, and a grant with no such limit, on every
  path that creates or renews one. The same pair covers agent expiry;
- the owner's opt-in warning before a binding's idle limit is reached.
"""

from __future__ import annotations

from typing import Self

from pydantic import BaseModel, Field, model_validator

_DAY = 86_400
_MAX_DURATION_S = 999 * _DAY


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

    default_expires_in_s: int | None = Field(
        default=None,
        ge=1,
        le=_MAX_DURATION_S,
        description=(
            "Default lifetime, in seconds, of a new credential grant whose creation sets no "
            "policy: it ends this long after it is granted. Unset (the open-source default): "
            "such a grant has no end date."
        ),
    )
    max_expires_in_s: int | None = Field(
        default=None,
        ge=1,
        le=_MAX_DURATION_S,
        description=(
            "Longest a credential grant may last, in seconds from when it is granted or "
            "renewed. When set, every grant must end: a grant with no end date, or one "
            "further out, is refused (422), and a creation that sets no policy gets the "
            "default (or this maximum when no default is set)."
        ),
    )
    default_idle_period_s: int | None = Field(
        default=None,
        ge=_DAY,
        le=_MAX_DURATION_S,
        description=(
            "Default idle limit, in seconds, of a new credential grant whose creation sets "
            "no policy. Unset: no idle limit."
        ),
    )
    max_idle_period_s: int | None = Field(
        default=None,
        ge=_DAY,
        le=_MAX_DURATION_S,
        description=(
            "Longest idle limit a credential grant may carry, in seconds. When set, every "
            "grant must carry one: none, or a longer one, is refused (422)."
        ),
    )
    single_use_by_default: bool = Field(
        default=False,
        description=(
            "Whether a new credential grant whose creation sets no policy allows a single "
            "call (a use count of 1)."
        ),
    )
    agent_default_expires_in_s: int | None = Field(
        default=None,
        ge=1,
        le=_MAX_DURATION_S,
        description=(
            "Default lifetime, in seconds, of an agent created or approved without an "
            "expiry. Unset: such an agent does not expire."
        ),
    )
    agent_max_expires_in_s: int | None = Field(
        default=None,
        ge=1,
        le=_MAX_DURATION_S,
        description=(
            "Longest an agent may last, in seconds from when its expiry is set. When set, "
            "every agent must expire: no expiry, or a later one, is refused (422)."
        ),
    )

    @model_validator(mode="after")
    def _defaults_within_maximums(self) -> Self:
        for default, maximum in (
            ("default_expires_in_s", "max_expires_in_s"),
            ("default_idle_period_s", "max_idle_period_s"),
            ("agent_default_expires_in_s", "agent_max_expires_in_s"),
        ):
            low, high = getattr(self, default), getattr(self, maximum)
            if low is not None and high is not None and low > high:
                raise ValueError(f"grant_expiry.{default} must not exceed {maximum}")
        return self
