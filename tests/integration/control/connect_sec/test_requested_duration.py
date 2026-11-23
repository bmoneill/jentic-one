"""A connect request can ask how long its access should last; the approver decides.

The ask is stored on the session and shown on the review page. The binding's
end date is the one the approver sends on confirm, worked out when they
confirm; a confirm without one binds with no expiry.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import SecretStr
from sqlalchemy import text

from jentic_one.control.services.integrations.connect_session_service import SecretConfirm
from jentic_one.control.services.integrations.flow_handlers.manual import ApiKeySecret
from jentic_one.shared.auth.agent_expiry import as_utc
from jentic_one.shared.context import Context
from tests.integration.control.connect_sec.support import (
    AGENT,
    AGENT_ID,
    API_BODY,
    KEY_SCHEME,
    OWNER,
    checks,
    client,
    connect,
    digest,
    import_spec,
    revision,
    session_row,
    svc,
)

pytestmark = pytest.mark.integration

_SECRET = "sk_duration_" + "D" * 20  # pragma: allowlist secret
_WEEK = 7 * 86_400


async def _binding_expiry(ctx: Context, credential_id: str) -> tuple[bool, datetime | None]:
    async with ctx.admin_db.session() as session:
        row = (
            await session.execute(
                text(
                    "SELECT expires_at FROM agent_credential_bindings"
                    " WHERE agent_id = :a AND credential_id = :c"
                ),
                {"a": AGENT_ID, "c": credential_id},
            )
        ).first()
    if row is None:
        return False, None
    return True, as_utc(row[0]) if row[0] is not None else None


async def _credential_of(ctx: Context, session_id: str) -> str:
    row = await session_row(ctx, session_id)
    assert row is not None
    return row.credential_id


async def _confirm(ctx: Context, session_id: str, expires_at: datetime | None) -> None:
    base = checks(await digest(ctx, session_id), revision_id=await revision(ctx, session_id))
    await svc(ctx).confirm_variant(
        session_id,
        poll_token=None,
        variant=SecretConfirm(
            kind="api_key",
            secret=ApiKeySecret(key=SecretStr(_SECRET)),
            checks=replace(base, expires_at=expires_at),
        ),
        identity=OWNER,
    )


async def test_the_requested_duration_is_shown_on_review(env: Context) -> None:
    await import_spec(env, KEY_SCHEME)
    created = await connect(env, requested_expires_in=_WEEK)

    review = await svc(env).get_review_data(created.session_id, poll_token=None, identity=OWNER)

    assert review.requested_expires_in == _WEEK


async def test_a_request_without_a_duration_asks_for_nothing(env: Context) -> None:
    await import_spec(env, KEY_SCHEME)
    created = await connect(env)

    review = await svc(env).get_review_data(created.session_id, poll_token=None, identity=OWNER)

    assert review.requested_expires_in is None


async def test_confirm_binds_with_the_approvers_end_date(env: Context) -> None:
    await import_spec(env, KEY_SCHEME)
    created = await connect(env, requested_expires_in=_WEEK)
    # The approver shortens the week the agent asked for to three days.
    end = (datetime.now(UTC) + timedelta(days=3)).replace(microsecond=0)

    await _confirm(env, created.session_id, end)

    bound, expires_at = await _binding_expiry(env, await _credential_of(env, created.session_id))
    assert bound
    assert expires_at == end


async def test_confirm_without_an_end_date_binds_with_no_expiry(env: Context) -> None:
    await import_spec(env, KEY_SCHEME)
    created = await connect(env, requested_expires_in=_WEEK)

    await _confirm(env, created.session_id, None)

    credential_id = await _credential_of(env, created.session_id)
    assert await _binding_expiry(env, credential_id) == (True, None)


async def test_http_connect_stores_the_duration_and_refuses_a_bad_one(env: Context) -> None:
    await import_spec(env, KEY_SCHEME)
    async with client(env, AGENT) as agent:
        refused = await agent.post(
            "/integrations:connect", json={**API_BODY, "requested_expires_in": 0}
        )
        assert refused.status_code == 422, refused.text
        created = await agent.post(
            "/integrations:connect", json={**API_BODY, "requested_expires_in": _WEEK}
        )
        assert created.status_code == 201, created.text
    async with client(env, OWNER) as owner:
        review = await owner.get(f"/connect-sessions/{created.json()['session_id']}")
    assert review.status_code == 200, review.text
    assert review.json()["requested_expires_in"] == _WEEK


async def test_http_confirm_refuses_an_end_date_in_the_past(env: Context) -> None:
    await import_spec(env, KEY_SCHEME)
    created = await connect(env)
    session_id = created.session_id
    body = {
        "kind": "api_key",
        "key": _SECRET,
        "permission_rules": [],
        "digest": await digest(env, session_id),
        "revision_id": await revision(env, session_id),
        "expected_agent_id": AGENT_ID,
        "expires_at": (datetime.now(UTC) - timedelta(minutes=1)).isoformat(),
    }
    async with client(env, OWNER) as owner:
        response = await owner.post(f"/connect-sessions/{session_id}:confirm", json=body)
    assert response.status_code == 422, response.text
    assert "expires_at must be in the future" in response.text


async def test_the_idle_limit_is_requested_and_set_on_confirm(env: Context) -> None:
    await import_spec(env, KEY_SCHEME)
    created = await connect(env, requested_max_idle_period=14 * 86_400)
    review = await svc(env).get_review_data(created.session_id, poll_token=None, identity=OWNER)
    assert review.requested_max_idle_period == 14 * 86_400

    base = checks(
        await digest(env, created.session_id), revision_id=await revision(env, created.session_id)
    )
    await svc(env).confirm_variant(
        created.session_id,
        poll_token=None,
        variant=SecretConfirm(
            kind="api_key",
            secret=ApiKeySecret(key=SecretStr(_SECRET)),
            checks=replace(base, max_idle_period=7 * 86_400, idle_warning=True),
        ),
        identity=OWNER,
    )

    credential_id = await _credential_of(env, created.session_id)
    async with env.admin_db.session() as session:
        limit, renewed, warning = (
            await session.execute(
                text(
                    "SELECT max_idle_period, renewed_at, idle_warning"
                    " FROM agent_credential_bindings WHERE agent_id = :a AND credential_id = :c"
                ),
                {"a": AGENT_ID, "c": credential_id},
            )
        ).one()
    assert limit == 7 * 86_400
    assert renewed is not None
    assert bool(warning) is True


async def test_http_refuses_an_idle_limit_under_a_day(env: Context) -> None:
    await import_spec(env, KEY_SCHEME)
    async with client(env, AGENT) as agent:
        refused = await agent.post(
            "/integrations:connect", json={**API_BODY, "requested_max_idle_period": 3_600}
        )
    assert refused.status_code == 422, refused.text
