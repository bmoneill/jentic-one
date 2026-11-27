"""A refused permission check logs who was refused, since the 403 body names no actor."""

from __future__ import annotations

import pytest
import structlog.testing
from jentic.problem_details import Forbidden

from jentic_one.shared.auth.identity import Identity
from jentic_one.shared.web.deps import enforce_identity_requirements


def test_a_permission_denial_logs_the_actor() -> None:
    identity = Identity(sub="usr_denied", permissions=["agents:read"])
    with structlog.testing.capture_logs() as logs, pytest.raises(Forbidden):
        enforce_identity_requirements(
            identity, instance="/credentials", required_permissions=["credentials:read"]
        )

    [line] = [entry for entry in logs if entry["event"] == "permission_denied"]
    assert line["actor_id"] == "usr_denied"
    assert line["required"] == ["credentials:read"]
    assert line["path"] == "/credentials"


def test_an_allowed_request_logs_nothing() -> None:
    identity = Identity(sub="usr_ok", permissions=["credentials:read"])
    with structlog.testing.capture_logs() as logs:
        enforce_identity_requirements(
            identity, instance="/credentials", required_permissions=["credentials:read"]
        )
    assert not [entry for entry in logs if entry["event"] == "permission_denied"]
