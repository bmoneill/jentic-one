"""An expired binding stops a new connect, and a credential read, for the same agent and API.

A binding past its ``expires_at`` no longer authorizes calls, and only its
operator can renew it. A new connect session for an API that the expired
credential covers would hand the agent that access again beside it, routing
around the expiry, so it is refused with 409 ``connect_session_binding_expired``
— at ``:connect``, and again at confirm. A suspension on the same binding is
reported first. An expired binding also stops widening the agent's credential
reads, like a suspended one. A binding with a future expiry is still active.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import SecretStr
from sqlalchemy import func, select, text

from jentic_one.control.core.schema.connect_sessions import ConnectSession
from jentic_one.control.core.schema.credentials import Credential
from jentic_one.control.repos.effects_repo import EffectsRepository
from jentic_one.control.repos.prerequisite_repo import PrerequisiteRepository
from jentic_one.control.services.credentials.errors import CredentialNotFoundError
from jentic_one.control.services.credentials.service import CredentialService
from jentic_one.control.services.integrations.connect_session_service import (
    ConfirmChecks,
    SecretConfirm,
)
from jentic_one.control.services.integrations.errors import (
    BindingExpiredError,
    BindingSuspendedError,
)
from jentic_one.control.services.integrations.flow_handlers.manual import ApiKeySecret
from jentic_one.shared.context import Context
from tests.integration.control.connect_sec.support import (
    AGENT,
    AGENT_ID,
    API_BODY,
    KEY_SCHEME,
    NAME,
    OWNER,
    RULES,
    TARGET,
    bind,
    client,
    connect,
    existing_credential,
    import_spec,
    is_bound,
    session_row,
    svc,
)

pytestmark = pytest.mark.integration

_SECRET = "sk_expired_" + "C" * 20  # pragma: allowlist secret
_PAST = datetime.now(UTC) - timedelta(days=1)
_FUTURE = datetime.now(UTC) + timedelta(days=30)


async def _set_binding(
    ctx: Context,
    agent_id: str,
    credential_id: str,
    *,
    expires_at: datetime | None,
    suspended: bool = False,
) -> None:
    async with ctx.admin_db.transaction() as session:
        await session.execute(
            text(
                "UPDATE agent_credential_bindings SET expires_at = :e, suspended = :s"
                " WHERE agent_id = :a AND credential_id = :c"
            ),
            {"e": expires_at, "s": suspended, "a": agent_id, "c": credential_id},
        )


async def _bound(
    ctx: Context,
    *,
    expires_at: datetime | None = _PAST,
    suspended: bool = False,
    name: str = NAME,
) -> str:
    """A credential of the owner covering the API, bound to the agent with the given state."""
    credential_id = await existing_credential(ctx)
    if name != NAME:
        async with ctx.control_db.transaction() as session:
            credential = await session.get(Credential, credential_id)
            assert credential is not None
            credential.api_name = name
    await bind(ctx, AGENT_ID, credential_id)
    await _set_binding(ctx, AGENT_ID, credential_id, expires_at=expires_at, suspended=suspended)
    return credential_id


async def _counts(ctx: Context) -> tuple[int, int]:
    async with ctx.control_db.session() as session:
        sessions = await session.scalar(select(func.count()).select_from(ConnectSession))
        credentials = await session.scalar(select(func.count()).select_from(Credential))
    return int(sessions or 0), int(credentials or 0)


# ---- :connect ---------------------------------------------------------------


async def test_agent_connect_is_refused_while_its_binding_is_expired(env: Context) -> None:
    await import_spec(env, KEY_SCHEME)
    await _bound(env)
    before = await _counts(env)

    with pytest.raises(BindingExpiredError):
        await connect(env)

    assert await _counts(env) == before


async def test_expired_binding_connect_is_409_over_http(env: Context) -> None:
    await import_spec(env, KEY_SCHEME)
    await _bound(env)

    async with client(env, AGENT) as agent:
        response = await agent.post(
            "/integrations:connect", json={**API_BODY, "reason": "needs the vault"}
        )

    assert response.status_code == 409, response.text
    assert response.json()["type"] == "connect_session_binding_expired"


async def test_owner_naming_the_agent_is_refused_too(env: Context) -> None:
    await import_spec(env, KEY_SCHEME)
    await _bound(env)

    with pytest.raises(BindingExpiredError):
        await svc(env).create_session(
            vendor_key="", agent_id=AGENT_ID, identity=OWNER, api_target=TARGET
        )


async def test_suspended_and_expired_is_reported_as_suspended(env: Context) -> None:
    await import_spec(env, KEY_SCHEME)
    await _bound(env, suspended=True)

    with pytest.raises(BindingSuspendedError):
        await connect(env)


async def test_suspension_on_one_binding_is_reported_before_expiry_on_another(
    env: Context,
) -> None:
    await import_spec(env, KEY_SCHEME)
    await _bound(env)
    suspended = await existing_credential(env, name="Suspended")
    await bind(env, AGENT_ID, suspended)
    await _set_binding(env, AGENT_ID, suspended, expires_at=None, suspended=True)

    with pytest.raises(BindingSuspendedError):
        await connect(env)


async def test_future_expiry_does_not_block_a_connect(env: Context) -> None:
    await import_spec(env, KEY_SCHEME)
    await _bound(env, expires_at=_FUTURE)

    created = await connect(env)

    assert await session_row(env, created.session_id) is not None


async def test_expired_binding_for_another_api_does_not_block_a_connect(env: Context) -> None:
    await import_spec(env, KEY_SCHEME)
    await _bound(env, name="some-other-api")

    created = await connect(env)

    assert await session_row(env, created.session_id) is not None


# ---- confirm ----------------------------------------------------------------


async def test_late_bound_confirm_is_refused_while_the_binding_is_expired(
    env: Context,
) -> None:
    await import_spec(env, KEY_SCHEME)
    created = await svc(env).create_session(
        vendor_key="",
        agent_id=None,
        identity=OWNER,
        api_target=TARGET,
        requested_permission_rules=RULES,
    )
    await _bound(env)
    service = svc(env)
    review = await service.get_review_data(
        created.session_id, poll_token=created.poll_token, identity=OWNER
    )

    with pytest.raises(BindingExpiredError):
        await service.confirm_variant(
            created.session_id,
            poll_token=created.poll_token,
            variant=SecretConfirm(
                kind="api_key",
                secret=ApiKeySecret(key=SecretStr(_SECRET)),
                checks=ConfirmChecks(
                    permission_rules=RULES,
                    expected_agent_id=None,
                    digest=review.digest,
                    revision_id=review.revision_id,
                    agent_id=AGENT_ID,
                ),
            ),
            identity=OWNER,
        )

    row = await session_row(env, created.session_id)
    assert row is not None and row.state == "created" and row.agent_id is None
    assert not await is_bound(env, AGENT_ID, row.credential_id)


# ---- repositories -----------------------------------------------------------


async def test_expired_credential_ids_list_only_unsuspended_expired_bindings(
    env: Context,
) -> None:
    expired = await _bound(env)
    await _bound(env, suspended=True)
    await _bound(env, expires_at=_FUTURE)
    await _bound(env, expires_at=None)

    async with env.admin_db.session() as session:
        ids = await EffectsRepository.list_expired_credential_ids(session, AGENT_ID)

    assert ids == [expired]


async def test_expiry_is_compared_against_the_given_now(env: Context) -> None:
    credential_id = await _bound(env, expires_at=_FUTURE)

    async with env.admin_db.session() as session:
        before = await EffectsRepository.list_expired_credential_ids(session, AGENT_ID)
        at = await EffectsRepository.list_expired_credential_ids(session, AGENT_ID, now=_FUTURE)
        readable_at = await PrerequisiteRepository.list_credential_ids_for_agent(
            session, agent_id=AGENT_ID, now=_FUTURE
        )

    assert before == []
    assert at == [credential_id]
    assert readable_at == []


# ---- credential reads -------------------------------------------------------


async def test_expired_binding_stops_widening_credential_reads(env: Context) -> None:
    expired = await _bound(env)
    active = await _bound(env, expires_at=_FUTURE)
    service = CredentialService(env)

    async with env.admin_db.session() as session:
        readable = await PrerequisiteRepository.list_credential_ids_for_agent(
            session, agent_id=AGENT_ID
        )
    assert readable == [active]

    assert (await service.get(active, identity=AGENT)).credential_id == active
    with pytest.raises(CredentialNotFoundError):
        await service.get(expired, identity=AGENT)


async def test_renewed_binding_widens_credential_reads_again(env: Context) -> None:
    credential_id = await _bound(env)
    await _set_binding(env, AGENT_ID, credential_id, expires_at=_FUTURE)

    view = await CredentialService(env).get(credential_id, identity=AGENT)

    assert view.credential_id == credential_id
