"""Credential reads write audit entries according to ``credentials.read_audit.policy``.

``cross_owner`` (the default) records only reads that return a credential the
caller did not create; ``all`` records every read; ``off`` records none.
Entries carry the returned credential ids and never any secret.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator
from typing import Any

import pytest
import structlog.testing
from sqlalchemy import delete, select

from jentic_one.admin.core.schema.audit import AuditEntry
from jentic_one.control.core.schema.credentials import Credential
from jentic_one.control.services.credentials.errors import CredentialNotFoundError
from jentic_one.control.services.credentials.read_audit import LIST_TARGET_ID
from jentic_one.control.services.credentials.service import CredentialService
from jentic_one.shared.auth.identity import Identity
from jentic_one.shared.context import Context
from jentic_one.shared.models import ActorType, StoredCredentialType
from jentic_one.shared.models.audit import AuditTargetType

pytestmark = pytest.mark.integration

_ADMIN = Identity(sub="usr_readaudit_admin", permissions=["org:admin"])
_OWNER = Identity(sub="usr_readaudit_owner", permissions=["credentials:read"])
_OTHER = "usr_readaudit_other"


@pytest.fixture()
async def clean(integration_context: Context) -> AsyncGenerator[None, None]:
    async def _wipe() -> None:
        async with integration_context.admin_db.transaction() as session:
            await session.execute(
                delete(AuditEntry).where(AuditEntry.target_type == AuditTargetType.CREDENTIAL.value)
            )
        async with integration_context.control_db.transaction() as session:
            await session.execute(delete(Credential).where(Credential.name.like("readaudit-%")))

    await _wipe()
    yield
    await _wipe()


def _policy(
    ctx: Context, monkeypatch: pytest.MonkeyPatch, policy: str, *, dedupe_seconds: float = 60.0
) -> None:
    read_audit = ctx.config.credentials.read_audit.model_copy(
        update={"policy": policy, "dedupe_seconds": dedupe_seconds}
    )
    credentials = ctx.config.credentials.model_copy(update={"read_audit": read_audit})
    monkeypatch.setattr(ctx, "_config", ctx.config.model_copy(update={"credentials": credentials}))


async def _credential(ctx: Context, created_by: str) -> str:
    credential_id = f"cred_ra{uuid.uuid4().hex[:20]}"
    async with ctx.control_db.transaction() as session:
        session.add(
            Credential(
                id=credential_id,
                type=StoredCredentialType.API_KEY.value,
                name=f"readaudit-{credential_id}",
                api_vendor="readaudit.example.com",
                created_by=created_by,
            )
        )
    return credential_id


async def _entries(ctx: Context) -> list[AuditEntry]:
    async with ctx.admin_db.session() as session:
        result = await session.execute(
            select(AuditEntry)
            .where(AuditEntry.target_type == AuditTargetType.CREDENTIAL.value)
            .order_by(AuditEntry.occurred_at.asc())
        )
        return list(result.scalars().all())


def _after(entry: AuditEntry) -> dict[str, Any]:
    assert isinstance(entry.after, dict)
    return entry.after


async def test_cross_owner_records_an_admin_listing_other_owners_credentials(
    integration_context: Context, clean: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = integration_context
    _policy(ctx, monkeypatch, "cross_owner")
    own = await _credential(ctx, _OWNER.sub)
    other = await _credential(ctx, _OTHER)
    svc = CredentialService(ctx)

    await svc.list_all(identity=_OWNER, vendor="readaudit.example.com")
    assert await _entries(ctx) == []  # an owner listing their own: no entry

    await svc.list_all(identity=_ADMIN, vendor="readaudit.example.com")
    [entry] = await _entries(ctx)
    assert entry.action == "list"
    assert entry.target_id == LIST_TARGET_ID
    assert entry.actor_id == _ADMIN.sub
    after = _after(entry)
    assert after["view"] == "list"
    assert after["credential_ids"] == sorted([own, other])
    assert after["cross_owner_count"] == 2


async def test_cross_owner_records_single_reads_of_another_owners_credential(
    integration_context: Context, clean: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = integration_context
    _policy(ctx, monkeypatch, "cross_owner")
    own = await _credential(ctx, _OWNER.sub)
    other = await _credential(ctx, _OTHER)
    svc = CredentialService(ctx)

    await svc.get(own, identity=_OWNER)
    await svc.get(own, identity=_ADMIN)
    await svc.list_agents(other, identity=_ADMIN)

    entries = await _entries(ctx)
    assert [(e.action, e.target_id, _after(e)["view"]) for e in entries] == [
        ("read", own, "detail"),
        ("read", other, "agents"),
    ]


async def test_an_agent_reading_its_owners_credential_is_not_cross_owner(
    integration_context: Context, clean: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = integration_context
    _policy(ctx, monkeypatch, "cross_owner")
    owned = await _credential(ctx, _OWNER.sub)
    agent = Identity(
        sub="agnt_readaudit",
        actor_type=ActorType.AGENT,
        parent_actor_id=_OWNER.sub,
        permissions=["org:admin"],
    )

    await CredentialService(ctx).get(owned, identity=agent)

    assert await _entries(ctx) == []


async def test_policy_all_records_own_reads_and_off_records_none(
    integration_context: Context, clean: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = integration_context
    own = await _credential(ctx, _OWNER.sub)
    svc = CredentialService(ctx)

    _policy(ctx, monkeypatch, "off")
    await svc.get(own, identity=_ADMIN)
    await svc.list_all(identity=_ADMIN, vendor="readaudit.example.com")
    assert await _entries(ctx) == []

    _policy(ctx, monkeypatch, "all")
    await svc.get(own, identity=_OWNER)
    [entry] = await _entries(ctx)
    assert entry.action == "read"
    assert _after(entry)["cross_owner_count"] == 0


async def test_identical_reads_are_deduplicated_within_the_window(
    integration_context: Context, clean: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = integration_context
    other = await _credential(ctx, _OTHER)
    svc = CredentialService(ctx)

    _policy(ctx, monkeypatch, "cross_owner", dedupe_seconds=60)
    await svc.get(other, identity=_ADMIN)
    await svc.get(other, identity=_ADMIN)
    assert len(await _entries(ctx)) == 1

    _policy(ctx, monkeypatch, "cross_owner", dedupe_seconds=0)
    await svc.get(other, identity=_ADMIN)
    await svc.get(other, identity=_ADMIN)
    assert len(await _entries(ctx)) == 3


async def test_a_not_found_probe_logs_the_actor(integration_context: Context, clean: None) -> None:
    other = await _credential(integration_context, _OTHER)
    with structlog.testing.capture_logs() as logs, pytest.raises(CredentialNotFoundError):
        await CredentialService(integration_context).get(other, identity=_OWNER)

    [line] = [entry for entry in logs if entry["event"] == "credential_read_not_found"]
    assert line["actor_id"] == _OWNER.sub
    assert line["credential_id"] == other
