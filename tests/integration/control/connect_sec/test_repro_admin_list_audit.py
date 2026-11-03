"""
SCRATCH repro (not for upstream or main): does an org:admin listing /credentials leave an audit row?
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select

from jentic_one.admin.core.schema.audit import AuditEntry
from jentic_one.control.web.app import create_app
from jentic_one.shared.context import Context
from jentic_one.shared.web.deps import resolve_identity
from tests.integration.control.connect_sec.support import (
    ADMIN,
    OTHER_OWNER_ID,
    OWNER,
    OWNER_ID,
    existing_credential,
)

pytestmark = pytest.mark.integration


async def _audit_count(ctx: Context) -> int:
    async with ctx.admin_db.session() as session:
        return (await session.execute(select(func.count()).select_from(AuditEntry))).scalar_one()


async def test_org_admin_list_credentials_leaves_no_audit(env: Context) -> None:
    mine = await existing_credential(env, name="owner-A-cred", owner_id=OWNER_ID)
    theirs = await existing_credential(env, name="owner-B-cred", owner_id=OTHER_OWNER_ID)

    app = create_app(env)
    app.dependency_overrides[resolve_identity] = lambda: ADMIN
    audit_before = await _audit_count(env)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://t") as http:
        resp = await http.get("/credentials", params={"limit": 200})

    audit_after = await _audit_count(env)
    ids = {c["credential_id"] for c in resp.json()["data"]}
    print(f"\nstatus={resp.status_code} returned={sorted(ids)}")
    print(f"audit rows before={audit_before} after={audit_after}")

    assert resp.status_code == 200
    assert {mine, theirs} <= ids  # admin enumerates other owners' credentials
    assert audit_after == audit_before  # ...and nothing was recorded

    # Control: a non-admin sees only their own rows.
    app.dependency_overrides[resolve_identity] = lambda: OWNER
    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://t") as http:
        scoped = {c["credential_id"] for c in (await http.get("/credentials")).json()["data"]}
    assert scoped == {mine}


async def test_non_admin_read_attempts_leave_what_trail(
    env: Context, caplog: pytest.LogCaptureFixture
) -> None:
    import logging

    import structlog.testing

    from jentic_one.shared.auth.identity import Identity

    mine = await existing_credential(env, name="owner-A-cred", owner_id=OWNER_ID)
    theirs = await existing_credential(env, name="owner-B-cred", owner_id=OTHER_OWNER_ID)
    no_cred_perms = Identity(sub="usr_sec_noperm", permissions=["agents:read"])

    app = create_app(env)
    caplog.set_level(logging.DEBUG)

    cases = [
        ("owner lists own", OWNER, "/credentials"),
        ("owner GETs another owner's cred", OWNER, f"/credentials/{theirs}"),
        ("no credentials perm lists", no_cred_perms, "/credentials"),
        ("no credentials perm GETs cred", no_cred_perms, f"/credentials/{mine}"),
    ]
    for label, identity, path in cases:
        app.dependency_overrides[resolve_identity] = lambda i=identity: i
        before = await _audit_count(env)
        caplog.clear()
        with structlog.testing.capture_logs() as slogs:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="https://t") as http:
                resp = await http.get(path)
        after = await _audit_count(env)
        std = [(r.name, r.levelname, r.getMessage()[:80]) for r in caplog.records]
        print(
            f"\n[{label}] status={resp.status_code} audit_delta={after - before}"
            f"\n  structlog={[(e['log_level'], e['event']) for e in slogs]}"
            f"\n  stdlib={std}"
        )


async def test_non_admin_reads_own_credential_trail(
    env: Context, caplog: pytest.LogCaptureFixture
) -> None:
    import logging

    import structlog.testing

    mine = await existing_credential(env, name="owner-A-cred", owner_id=OWNER_ID)
    app = create_app(env)
    app.dependency_overrides[resolve_identity] = lambda: OWNER
    caplog.set_level(logging.INFO)
    for path in ("/credentials", f"/credentials/{mine}", f"/credentials/{mine}/agents"):
        before = await _audit_count(env)
        caplog.clear()
        with structlog.testing.capture_logs() as slogs:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="https://t") as http:
                resp = await http.get(path)
        std = [(r.name, r.levelname) for r in caplog.records if r.name != "httpx"]
        print(
            f"\n[{path.replace(mine, '<id>')}] status={resp.status_code}"
            f" audit_delta={await _audit_count(env) - before}"
            f" structlog={[e['event'] for e in slogs]} server_stdlib={std}"
        )
