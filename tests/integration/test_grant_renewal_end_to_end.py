"""End-to-end: a call through an ended binding is held for renewal (D14).

Against a real Context (admin and control DBs):

1. the broker's hold path files a ``grant_renewal`` hold for the agent's call
   instead of the 403, and answers the 202 held envelope;
2. while it is pending, another call through the binding gets the 403 with
   the review link, and the pending renewal counts against no cap;
3. a reviewer who may renew the binding approves with a fresh policy: the
   binding is renewed in place, and the worker runs the call once;
4. a denial leaves the binding ended, and later calls get the 403 saying so
   until the owner renews it from the console;
5. a reviewer who may decide but not renew (the credential is someone
   else's) can only deny.

The upstream leg is a recording execution handler, as in the require-approval
end-to-end test.
"""

from __future__ import annotations

import json
from collections.abc import AsyncGenerator, AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select, update
from starlette.requests import Request

from jentic_one.admin.core.schema.agent_credential_bindings import AgentCredentialBinding
from jentic_one.admin.core.schema.agents import Agent
from jentic_one.admin.core.schema.events import Event
from jentic_one.admin.core.schema.held_executions import HeldExecution
from jentic_one.admin.core.schema.job_results import JobResult
from jentic_one.admin.core.schema.jobs import Job
from jentic_one.admin.core.schema.users import User
from jentic_one.admin.repos import AgentRepository, UserRepository
from jentic_one.admin.web.app import create_app
from jentic_one.auth.services.grant_renewer import AgentGrantRenewer
from jentic_one.broker.core.errors import CredentialBindingExpiredError
from jentic_one.broker.core.schemas import ExecuteRequestContext
from jentic_one.broker.web.routers.execute import _hold_call, _renewable
from jentic_one.control.core.schema.credentials import Credential
from jentic_one.shared.auth.agent_expiry import as_utc
from jentic_one.shared.auth.grant_renewal import GrantRenewalPolicy
from jentic_one.shared.auth.identity import Identity
from jentic_one.shared.config import WorkerConfig
from jentic_one.shared.context import Context
from jentic_one.shared.jobs.handlers import JobHandlerRegistry, JobResultPayload
from jentic_one.shared.jobs.hold import GRANT_RENEWAL_AGENT_DIRECTIVE, file_hold
from jentic_one.shared.jobs.worker import WorkerLoop
from jentic_one.shared.models import (
    ActorStatus,
    ActorType,
    InviteState,
    JobKind,
    JobStatus,
    StoredCredentialType,
)
from jentic_one.shared.models.held_executions import HeldExecutionKind
from jentic_one.shared.web.deps import resolve_identity

pytestmark = pytest.mark.integration

_URL = "https://api.example.com/v1/charges"
_CREDENTIAL = "cred_renew_e2e"
_OTHERS_CREDENTIAL = "cred_renew_others"


@dataclass(frozen=True)
class _Parties:
    owner: Identity
    agent: Identity
    admin: Identity


class _RecordingHandler:
    def __init__(self) -> None:
        self.calls = 0

    async def execute(
        self,
        job_id: str,
        session: Any,
        *,
        payload: dict[str, Any] | None = None,
        created_by: str | None = None,
        actor_type: str | None = None,
    ) -> JobResultPayload:
        self.calls += 1
        return JobResultPayload(
            body={"execution_id": "exec_renew", "status": "completed", "http_status": 200}
        )


@pytest.fixture()
async def parties(integration_context: Context) -> AsyncGenerator[_Parties, None]:
    """An owner, their agent and an admin; two credentials, each bound and ended."""
    ctx = integration_context

    async def _clean() -> None:
        async with ctx.admin_db.transaction() as session:
            await session.execute(delete(HeldExecution))
            await session.execute(delete(JobResult))
            await session.execute(delete(Job))
            await session.execute(delete(Event).where(Event.type.like("execution.approval_%")))
            await session.execute(
                delete(AgentCredentialBinding).where(
                    AgentCredentialBinding.credential_id.in_([_CREDENTIAL, _OTHERS_CREDENTIAL])
                )
            )
        async with ctx.control_db.transaction() as session:
            await session.execute(
                delete(Credential).where(Credential.id.in_([_CREDENTIAL, _OTHERS_CREDENTIAL]))
            )

    await _clean()
    async with ctx.admin_db.transaction() as session:
        owner = await UserRepository.create(
            session,
            email="renew-owner@test.local",
            first_name="Renew",
            last_name="Owner",
            invite_state=InviteState.REDEEMED,
            created_by="usr_test",
        )
        agent = await AgentRepository.create(
            session,
            name="renew-agent",
            owner_id=owner.id,
            registered_by=owner.id,
            created_by=owner.id,
            status=ActorStatus.ACTIVE,
        )
        owner_id, agent_id = owner.id, agent.id
        ended = datetime.now(UTC) - timedelta(days=1)
        for credential_id in (_CREDENTIAL, _OTHERS_CREDENTIAL):
            session.add(
                AgentCredentialBinding(
                    agent_id=agent_id,
                    credential_id=credential_id,
                    created_by=owner_id,
                    bound_at=ended - timedelta(days=30),
                    renewed_at=ended - timedelta(days=30),
                    expires_at=ended,
                )
            )
    async with ctx.control_db.transaction() as session:
        for credential_id, creator in ((_CREDENTIAL, owner_id), (_OTHERS_CREDENTIAL, "usr_else")):
            session.add(
                Credential(
                    id=credential_id,
                    type=StoredCredentialType.API_KEY,
                    name=f"key-{credential_id}",
                    api_vendor="api.example.com",
                    api_name="payments",
                    api_version="1",
                    created_by=creator,
                )
            )
    yield _Parties(
        owner=Identity(
            sub=owner_id,
            email="renew-owner@test.local",
            permissions=["agents:read", "agents:write"],
        ),
        agent=Identity(
            sub=agent_id, permissions=[], actor_type=ActorType.AGENT, parent_actor_id=owner_id
        ),
        admin=Identity(sub="usr_renew_admin", permissions=["org:admin"]),
    )
    await _clean()
    async with ctx.admin_db.transaction() as session:
        await session.execute(delete(Agent).where(Agent.id == agent_id))
        await session.execute(delete(User).where(User.id == owner_id))


def _request(body: bytes = b'{"amount": 500}') -> Request:
    sent = False

    async def receive() -> dict[str, Any]:
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    scope = {
        "type": "http",
        "method": "POST",
        "scheme": "http",
        "server": ("broker.local", 8080),
        "path": "/api.example.com/v1/charges",
        "raw_path": b"/api.example.com/v1/charges",
        "root_path": "",
        "query_string": b"",
        "headers": [(b"content-type", b"application/json"), (b"host", b"broker.local:8080")],
    }
    return Request(scope, receive)


def _ended(credential_id: str) -> CredentialBindingExpiredError:
    """The resolver's 403 for the agent's ended binding to ``credential_id``."""
    error = CredentialBindingExpiredError(
        "The credential binding for this API has expired: its end date passed",
        extra={"expired_reason": "end_date"},
        instance="/api.example.com/v1/charges",
    )
    error.ended_credential_id = credential_id
    return error


async def _call(
    ctx: Context, agent: Identity, *, credential_id: str = _CREDENTIAL, body: bytes = b"{}"
) -> dict[str, Any]:
    ctx_req = ExecuteRequestContext(
        upstream_url=_URL,
        method="POST",
        trace_id="f" * 32,
        api_vendor="api.example.com",
        api_name="payments",
        api_version="1",
    )
    response = await _hold_call(
        _request(body),
        ctx_req,
        ctx,
        agent,
        credential_id=credential_id,
        allowed_credential_ids=[credential_id],
        matched_rule_id=None,
        ended=_ended(credential_id),
    )
    assert response.status_code == 202
    return dict(json.loads(bytes(response.body)))


@asynccontextmanager
async def _admin_client(
    ctx: Context, identity: Identity, *, renewer: bool = True
) -> AsyncIterator[AsyncClient]:
    app = create_app(ctx)
    # A split deployment's admin process cannot read the control DB: no renewer.
    app.state.grant_renewer = AgentGrantRenewer(ctx) if renewer else None
    app.dependency_overrides[resolve_identity] = lambda: identity
    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://testserver") as c:
        yield c


def _worker(ctx: Context, handler: _RecordingHandler) -> WorkerLoop:
    registry = JobHandlerRegistry()
    registry.register(JobKind.EXECUTION, handler)
    return WorkerLoop(
        ctx.admin_db,
        registry,
        worker_config=WorkerConfig(max_attempts=5),
        approved_result_retention_seconds=3600,
    )


async def _binding(ctx: Context, credential_id: str = _CREDENTIAL) -> AgentCredentialBinding:
    async with ctx.admin_db.session() as session:
        row = (
            await session.execute(
                select(AgentCredentialBinding).where(
                    AgentCredentialBinding.credential_id == credential_id
                )
            )
        ).scalar_one()
        return row


async def test_approving_a_renewal_renews_the_binding_and_runs_the_call(
    integration_context: Context, parties: _Parties
) -> None:
    ctx = integration_context
    envelope = await _call(ctx, parties.agent)
    held_id = envelope["held_execution_id"]
    assert envelope["status"] == "held"
    assert envelope["agent_directive"]["human_readable_instruction"] == (
        GRANT_RENEWAL_AGENT_DIRECTIVE
    )

    # The same call again joins the hold; a different one gets the 403 with its link.
    assert (await _call(ctx, parties.agent))["held_execution_id"] == held_id
    with pytest.raises(CredentialBindingExpiredError) as other:
        await _call(ctx, parties.agent, body=b'{"amount": 1}')
    assert other.value.extra["held_execution_id"] == held_id
    assert str(other.value.extra["review_url"]).endswith(f"/app/agents/approvals/{held_id}")
    assert other.value.extra["expired_reason"] == "end_date"

    async with _admin_client(ctx, parties.owner) as client:
        detail = (await client.get(f"/executions/holds/{held_id}")).json()
        assert detail["kind"] == "grant_renewal"
        assert detail["renewal"]["expired_reason"] == "end_date"
        assert detail["renewal"]["can_renew"] is True
        # Approving needs the fresh policy.
        bare = await client.post(
            f"/executions/holds/{held_id}:decide", json={"decision": "approve"}
        )
        assert bare.status_code == 422, bare.text
        assert bare.json()["type"].endswith("held_execution_renewal_invalid")
        until = datetime.now(UTC) + timedelta(days=7)
        decided = await client.post(
            f"/executions/holds/{held_id}:decide",
            json={
                "decision": "approve",
                "renewal": {"expires_at": until.isoformat(), "max_quota": 1},
            },
        )
    assert decided.status_code == 200, decided.text
    assert decided.json()["state"] == "approved"
    assert decided.json()["execution_status"] == JobStatus.QUEUED

    binding = await _binding(ctx)
    assert as_utc(binding.expires_at) == until  # type: ignore[arg-type]
    assert (binding.max_quota, binding.quota_remaining) == (1, 1)

    handler = _RecordingHandler()
    worker = _worker(ctx, handler)
    assert await worker._tick() is True
    assert handler.calls == 1


async def test_a_split_deployment_renews_through_the_binding_then_approves(
    integration_context: Context, parties: _Parties
) -> None:
    """Without a renewer, the reviewer renews via the binding's endpoint, then approves."""
    ctx = integration_context
    held_id = (await _call(ctx, parties.agent))["held_execution_id"]
    async with _admin_client(ctx, parties.owner, renewer=False) as client:
        detail = (await client.get(f"/executions/holds/{held_id}")).json()
        assert detail["renewal"]["renew_on_decide"] is False
        # Renewing here is unavailable, and a bare approve can't release an ended binding.
        here = await client.post(
            f"/executions/holds/{held_id}:decide",
            json={"decision": "approve", "renewal": {}},
        )
        assert here.status_code == 503, here.text
        bare = await client.post(
            f"/executions/holds/{held_id}:decide", json={"decision": "approve"}
        )
        assert bare.status_code == 422, bare.text
        # The auth surface's renew endpoint, then the approval.
        await AgentGrantRenewer(ctx).renew(
            identity=parties.owner,
            agent_id=parties.agent.sub,
            credential_id=_CREDENTIAL,
            policy=GrantRenewalPolicy(expires_at=datetime.now(UTC) + timedelta(days=7)),
        )
        decided = await client.post(
            f"/executions/holds/{held_id}:decide", json={"decision": "approve"}
        )
    assert decided.status_code == 200, decided.text
    assert decided.json()["execution_status"] == JobStatus.QUEUED
    handler = _RecordingHandler()
    assert await _worker(ctx, handler)._tick() is True
    assert handler.calls == 1


async def test_renewing_without_running_fails_the_stale_call(
    integration_context: Context, parties: _Parties
) -> None:
    ctx = integration_context
    held_id = (await _call(ctx, parties.agent))["held_execution_id"]
    async with _admin_client(ctx, parties.owner) as client:
        decided = await client.post(
            f"/executions/holds/{held_id}:decide",
            json={"decision": "approve", "renewal": {"expires_at": None}, "run": False},
        )
        assert decided.status_code == 200, decided.text
        assert decided.json()["execution_status"] == JobStatus.FAILED
        result = await client.get(f"/executions/holds/{held_id}/result")
    assert result.json()["type"].endswith("approval_renewed_without_run")
    # Fresh access with no limits: the end date is gone.
    assert (await _binding(ctx)).expires_at is None
    handler = _RecordingHandler()
    assert await _worker(ctx, handler)._tick() is False


async def test_a_denied_renewal_refuses_calls_until_the_owner_renews(
    integration_context: Context, parties: _Parties
) -> None:
    ctx = integration_context
    held_id = (await _call(ctx, parties.agent))["held_execution_id"]
    async with _admin_client(ctx, parties.owner) as client:
        decided = await client.post(
            f"/executions/holds/{held_id}:decide", json={"decision": "deny"}
        )
    assert decided.status_code == 200, decided.text
    assert (await _binding(ctx)).expires_at is not None

    with pytest.raises(CredentialBindingExpiredError) as refused:
        await _call(ctx, parties.agent, body=b'{"amount": 2}')
    assert "denied on" in refused.value.detail
    assert refused.value.extra["renewal_denied_at"]

    # The owner renews from the console; when it ends again, a new renewal is filed.
    async with ctx.admin_db.transaction() as session:
        await session.execute(
            update(AgentCredentialBinding)
            .where(AgentCredentialBinding.credential_id == _CREDENTIAL)
            .values(renewed_at=datetime.now(UTC) + timedelta(seconds=1))
        )
    again = await _call(ctx, parties.agent, body=b'{"amount": 3}')
    assert again["held_execution_id"] != held_id


async def test_only_a_reviewer_who_may_renew_can_grant_fresh_access(
    integration_context: Context, parties: _Parties
) -> None:
    ctx = integration_context
    held_id = (await _call(ctx, parties.agent, credential_id=_OTHERS_CREDENTIAL))[
        "held_execution_id"
    ]
    renewal = {"decision": "approve", "renewal": {"max_idle_period": 14 * 86_400}}
    # The agent's owner may decide, but the credential is someone else's.
    async with _admin_client(ctx, parties.owner) as client:
        detail = (await client.get(f"/executions/holds/{held_id}")).json()
        assert detail["renewal"]["can_renew"] is False
        refused = await client.post(f"/executions/holds/{held_id}:decide", json=renewal)
    assert refused.status_code == 403, refused.text
    assert refused.json()["type"].endswith("held_execution_renewal_forbidden")
    assert (await _binding(ctx, _OTHERS_CREDENTIAL)).max_idle_period is None

    async with _admin_client(ctx, parties.admin) as client:
        approved = await client.post(f"/executions/holds/{held_id}:decide", json=renewal)
    assert approved.status_code == 200, approved.text
    assert (await _binding(ctx, _OTHERS_CREDENTIAL)).max_idle_period == 14 * 86_400


async def test_fresh_access_respects_the_org_maximum(
    integration_context: Context, parties: _Parties, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = integration_context
    monkeypatch.setattr(ctx.config.grant_expiry, "max_expires_in_s", 7 * 86_400)
    held_id = (await _call(ctx, parties.agent))["held_execution_id"]
    async with _admin_client(ctx, parties.owner) as client:
        # "No expiry" is refused under a maximum.
        refused = await client.post(
            f"/executions/holds/{held_id}:decide",
            json={"decision": "approve", "renewal": {"expires_at": None}},
        )
        assert refused.status_code == 422, refused.text
        assert refused.json()["type"].endswith("grant_policy_limit_exceeded")
        detail = (await client.get(f"/executions/holds/{held_id}")).json()
        assert detail["state"] == "pending"
        # An end date left out is the renewal default, which never exceeds the maximum.
        approved = await client.post(
            f"/executions/holds/{held_id}:decide",
            json={"decision": "approve", "renewal": {}},
        )
        assert approved.status_code == 200, approved.text
    expires_at = (await _binding(ctx)).expires_at
    assert expires_at is not None
    assert as_utc(expires_at) <= datetime.now(UTC) + timedelta(days=7)


async def test_renewal_holds_never_count_against_the_pending_cap(
    integration_context: Context, parties: _Parties
) -> None:
    ctx = integration_context
    async with ctx.admin_db.transaction() as session:
        hold = await file_hold(
            session,
            agent_id=parties.agent.sub,
            actor_type=ActorType.AGENT.value,
            credential_id=_CREDENTIAL,
            matched_rule_id=None,
            api_vendor="api.example.com",
            api_name="payments",
            api_version="1",
            operation_id=None,
            method="POST",
            path="/v1/charges",
            body=b"{}",
            trace_id=None,
            execution_id="exec_cap",
            payload={},
            ttl_seconds=3600,
            max_pending=0,
            kind=HeldExecutionKind.GRANT_RENEWAL,
        )
    assert hold.joined is False


async def test_a_binding_set_to_refuse_is_never_held(
    integration_context: Context, parties: _Parties
) -> None:
    """``after_expiry: refuse`` keeps the plain 403: the agent asks its owner instead."""
    ended = _ended(_CREDENTIAL)
    assert _renewable(integration_context, parties.agent, ended)
    ended.holds_for_renewal = False
    assert not _renewable(integration_context, parties.agent, ended)
