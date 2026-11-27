"""One absolute deadline for everything a request or queued job does before it is dispatched.

Credential resolution, the refresh lock, write-key preparation and cookie
encryption all run ahead of the upstream call. Each used to have its own
budget (or none), so key preparation could outlive the caller and a refresh
could start after the request had already timed out. The web edge binds one
:class:`RequestDeadline` for the request; every step reads it with
:func:`current_deadline` and bounds its own wait by what is left.

It is a ``ContextVar`` so it follows the request into child tasks (the
shielded token refresh copies the context when it is created) without
threading a parameter through every signature.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass

from jentic_one.shared.crypto.errors import EncryptionUnavailableError


class RequestDeadlineExpiredError(Exception):
    """The request's deadline passed before its upstream call was made.

    Nothing was sent, so the call may be retried. Distinct from encryption
    backend errors: running out of time is not a backend outage.
    """


class EncryptionDeadlineError(EncryptionUnavailableError, RequestDeadlineExpiredError):
    """The request's deadline ran out while it was waiting on the encryption backend.

    Both an encryption-unavailable error (backend latency used up the budget, so
    callers answer 503 ``encryption_unavailable`` with retry guidance) and a
    deadline error (nothing was sent; deadline-aware callers treat it as expiry).
    """


@dataclass(frozen=True, slots=True)
class RequestDeadline:
    """A point on the monotonic clock after which the request has timed out."""

    at: float

    @classmethod
    def after(cls, seconds: float) -> RequestDeadline:
        return cls(at=time.monotonic() + seconds)

    def remaining(self) -> float:
        """Seconds left; never negative."""
        return max(0.0, self.at - time.monotonic())

    @property
    def expired(self) -> bool:
        return time.monotonic() >= self.at


_current: ContextVar[RequestDeadline | None] = ContextVar("broker_request_deadline", default=None)


def current_deadline() -> RequestDeadline | None:
    """The deadline bound for this request, or ``None`` when none is set."""
    return _current.get()


def deadline_expired() -> bool:
    """Whether a deadline is bound for this request and has passed."""
    deadline = _current.get()
    return deadline is not None and deadline.expired


def remaining_budget(default: float | None = None) -> float | None:
    """Seconds left on the bound deadline, or *default* when none is bound."""
    deadline = _current.get()
    return default if deadline is None else deadline.remaining()


@contextmanager
def bind_request_deadline(seconds: float) -> Iterator[RequestDeadline | None]:
    """Bind a deadline *seconds* from now for the enclosed work (``<= 0`` binds none)."""
    if seconds <= 0:
        yield None
        return
    deadline = RequestDeadline.after(seconds)
    token = _current.set(deadline)
    try:
        yield deadline
    finally:
        _current.reset(token)


_EXPIRED = "request deadline expired before the upstream call could be made"


def ensure_not_expired() -> None:
    """Raise :class:`RequestDeadlineExpiredError` if the bound deadline has passed.

    Call this immediately before an irreversible step (the vendor or upstream
    send). The failure is pre-send, so nothing has been dispatched and the call
    may be retried.
    """
    if deadline_expired():
        raise RequestDeadlineExpiredError(_EXPIRED)


async def within_deadline[T](awaitable: Awaitable[T]) -> T:
    """Await *awaitable*, giving up when the bound deadline runs out.

    With no deadline bound the awaitable runs unbounded. When the deadline
    expires the awaitable is cancelled and :class:`RequestDeadlineExpiredError`
    is raised. A ``TimeoutError`` raised by the awaitable itself propagates
    unchanged, so a backend's own timeout is not mistaken for the deadline.
    """
    return await _run_bounded(awaitable, lambda: RequestDeadlineExpiredError(_EXPIRED))


async def within_encryption_deadline[T](awaitable: Awaitable[T], *, backend: str) -> T:
    """Await an encryption backend call, giving up when the bound deadline runs out.

    Like :func:`within_deadline`, but expiry raises :class:`EncryptionDeadlineError`:
    the time ran out inside the backend, so callers report the backend as
    unavailable rather than a general deadline expiry.
    """
    return await _run_bounded(
        awaitable, lambda: EncryptionDeadlineError(_ENCRYPTION_EXPIRED, backend=backend)
    )


_ENCRYPTION_EXPIRED = "request deadline expired while waiting on the encryption backend"


async def _run_bounded[T](awaitable: Awaitable[T], on_expiry: Callable[[], Exception]) -> T:
    budget = remaining_budget()
    if budget is None:
        return await awaitable
    timeout = asyncio.timeout(budget)
    try:
        async with timeout:
            return await awaitable
    except TimeoutError:
        if timeout.expired():
            raise on_expiry() from None
        raise
