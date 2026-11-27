"""Broker problems for encryption backend failures and pre-dispatch deadline expiry.

Every path that can raise :class:`EncryptionUnavailableError`,
:class:`EncryptionAccessDeniedError` or :class:`RequestDeadlineExpiredError`
before the upstream call builds its problem here, so the agent always gets the
same status, type and directive:

- backend unavailable, including a deadline that ran out while waiting on the
  backend: 503 ``encryption_unavailable``, ``wait`` (``Retry-After`` when the
  backend gave a delay);
- backend denied access: 503 ``encryption_access_denied``, ``prompt_human``;
- deadline expired anywhere else before dispatch: 504 ``deadline_exceeded``, ``wait``.

All three are pre-send: nothing reached the upstream.
"""

from __future__ import annotations

import math
from typing import Any

from jentic_one.broker.core.directives import AgentDirective
from jentic_one.broker.core.errors import (
    BrokerError,
    CredentialEncryptionAccessDeniedError,
    CredentialEncryptionUnavailableError,
    DeadlineExceededError,
)
from jentic_one.shared.crypto.errors import (
    EncryptionAccessDeniedError,
    EncryptionBackendError,
    EncryptionUnavailableError,
)
from jentic_one.shared.deadline import RequestDeadlineExpiredError


def retry_after(exc: EncryptionUnavailableError) -> tuple[dict[str, Any], dict[str, str]]:
    """Directive parameters and headers for the backend's retry hint (at least 1 s)."""
    if exc.retry_after_s is None:
        return {}, {}
    seconds = max(1, math.ceil(exc.retry_after_s))
    return {"retry_after_seconds": seconds}, {"Retry-After": str(seconds)}


def encryption_unavailable_error(
    exc: EncryptionUnavailableError,
    *,
    detail: str,
    extra: dict[str, Any] | None = None,
    instance: str | None = None,
) -> CredentialEncryptionUnavailableError:
    """The retryable 503 for a transient encryption backend failure."""
    parameters, headers = retry_after(exc)
    return CredentialEncryptionUnavailableError(
        detail=detail,
        extra={**(extra or {}), "backend": exc.backend},
        headers=headers,
        instance=instance,
        pre_send=True,
        directive=AgentDirective(
            strategy="wait",
            parameters=parameters,
            human_readable_instruction=(
                "The broker could not reach its encryption backend, so the call "
                "was not sent. Wait briefly (Retry-After when given) and retry."
            ),
        ),
    )


def encryption_access_denied_error(
    exc: EncryptionAccessDeniedError,
    *,
    detail: str,
    extra: dict[str, Any] | None = None,
    parameters: dict[str, Any] | None = None,
    instance: str | None = None,
) -> CredentialEncryptionAccessDeniedError:
    """The non-retryable 503 for an encryption backend that refused access."""
    return CredentialEncryptionAccessDeniedError(
        detail=detail,
        extra={**(extra or {}), "backend": exc.backend},
        instance=instance,
        pre_send=True,
        directive=AgentDirective(
            strategy="prompt_human",
            parameters=parameters or {},
            human_readable_instruction=(
                "The broker's encryption backend denied access, so the call was not "
                "sent. Ask an operator to restore access to the encryption key; "
                "retrying will not fix this."
            ),
        ),
    )


def deadline_expired_error(
    deadline_s: float, *, instance: str | None = None
) -> DeadlineExceededError:
    """The 504 for a request whose deadline passed before it was dispatched."""
    return DeadlineExceededError(
        detail=(
            f"The request used up the broker's {deadline_s:g}s deadline before the "
            "upstream call could be made; nothing was sent."
        ),
        type="deadline_exceeded",
        instance=instance,
        pre_send=True,
        directive=AgentDirective(
            strategy="wait",
            parameters={"deadline_seconds": deadline_s},
            human_readable_instruction=(
                "The request ran out of time before it was sent upstream; wait "
                "briefly and retry, or issue the call asynchronously."
            ),
        ),
    )


def map_predispatch_error(
    exc: EncryptionBackendError | RequestDeadlineExpiredError,
    *,
    deadline_s: float,
    instance: str | None = None,
) -> BrokerError:
    """Map a pre-dispatch backend or deadline failure to its broker problem.

    An encryption error wins over a deadline: a deadline that ran out *inside* an
    encryption call (``EncryptionDeadlineError`` is both) is backend latency, so it
    is a 503 ``encryption_unavailable``. Expiry anywhere else is a 504.
    """
    if not isinstance(exc, EncryptionBackendError):
        return deadline_expired_error(deadline_s, instance=instance)
    if isinstance(exc, EncryptionAccessDeniedError):
        return encryption_access_denied_error(
            exc,
            detail=f"The encryption backend '{exc.backend}' denied access; the call was not sent",
            instance=instance,
        )
    if isinstance(exc, EncryptionUnavailableError):
        return encryption_unavailable_error(
            exc,
            detail=(
                f"The encryption backend '{exc.backend}' is temporarily unavailable; "
                "the call was not sent"
            ),
            instance=instance,
        )
    # Any other backend error is treated as transient.
    return encryption_unavailable_error(
        EncryptionUnavailableError(str(exc), backend=exc.backend, key_id=exc.key_id),
        detail=(f"The encryption backend '{exc.backend}' failed; the call was not sent"),
        instance=instance,
    )
