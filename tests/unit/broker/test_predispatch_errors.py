"""Pre-dispatch failures: deadline expiry and encryption backend errors map to distinct problems."""

from __future__ import annotations

import asyncio
import time

import pytest

from jentic_one.broker.core.encryption_errors import map_predispatch_error
from jentic_one.broker.core.problem import status_for_broker_error
from jentic_one.shared.crypto.errors import (
    EncryptionAccessDeniedError,
    EncryptionBackendError,
    EncryptionUnavailableError,
)
from jentic_one.shared.deadline import (
    RequestDeadlineExpiredError,
    bind_request_deadline,
    deadline_expired,
    ensure_not_expired,
    within_deadline,
)


def test_deadline_expiry_is_a_504_not_an_encryption_outage() -> None:
    err = map_predispatch_error(RequestDeadlineExpiredError("late"), deadline_s=30.0)
    assert status_for_broker_error(err) == 504
    assert err.type == "deadline_exceeded"
    assert err.pre_send is True
    assert err.directive is not None
    assert err.directive.strategy == "wait"
    assert "encryption" not in err.detail


@pytest.mark.parametrize(("retry_after_s", "header"), [(2.5, "3"), (0.2, "1"), (None, None)])
def test_backend_unavailable_is_a_retryable_503(
    retry_after_s: float | None, header: str | None
) -> None:
    exc = EncryptionUnavailableError("down", backend="kms", retry_after_s=retry_after_s)
    err = map_predispatch_error(exc, deadline_s=30.0, instance="/x")
    assert status_for_broker_error(err) == 503
    assert err.type == "encryption_unavailable"
    assert err.headers.get("Retry-After") == header
    assert err.directive is not None and err.directive.strategy == "wait"
    assert err.extra["backend"] == "kms"
    assert err.instance == "/x"


def test_backend_denied_is_a_non_retryable_503() -> None:
    err = map_predispatch_error(
        EncryptionAccessDeniedError("denied", backend="kms", key_id="k1"), deadline_s=30.0
    )
    assert status_for_broker_error(err) == 503
    assert err.type == "encryption_access_denied"
    assert err.directive is not None and err.directive.strategy == "prompt_human"
    assert "k1" not in err.detail


def test_an_unknown_backend_error_is_treated_as_transient() -> None:
    err = map_predispatch_error(EncryptionBackendError("odd", backend="kms"), deadline_s=30.0)
    assert err.type == "encryption_unavailable"


def test_ensure_not_expired_raises_the_deadline_error() -> None:
    ensure_not_expired()  # no deadline bound: never raises
    with bind_request_deadline(0.000001):
        time.sleep(0.01)
        assert deadline_expired() is True
        with pytest.raises(RequestDeadlineExpiredError):
            ensure_not_expired()
    assert deadline_expired() is False


async def test_within_deadline_raises_the_deadline_error_on_expiry() -> None:
    with bind_request_deadline(0.02), pytest.raises(RequestDeadlineExpiredError):
        await within_deadline(asyncio.sleep(1))


async def test_within_deadline_does_not_relabel_the_awaitables_own_timeout() -> None:
    async def times_out() -> None:
        raise TimeoutError("backend socket timeout")

    with bind_request_deadline(10.0), pytest.raises(TimeoutError, match="backend socket"):
        await within_deadline(times_out())
