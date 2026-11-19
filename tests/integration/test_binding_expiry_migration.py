"""Upgrade/downgrade of the ``agent_credential_bindings.expires_at`` migration.

Downgrading drops the column, so it first suspends every binding whose expiry
has already passed (reason ``binding_expired``): a code rollback must fail
closed, never revive lapsed access. Bindings with no expiry or a future expiry
are left alone, and re-upgrading restores the column with no policy backfilled.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta

import pytest
from alembic import command
from sqlalchemy import inspect, text

from jentic_one.shared.config import AppConfig
from jentic_one.shared.db.session import DatabaseSession
from tests.harness.postgres import alembic_config_for

pytestmark = pytest.mark.integration

_REVISION = "e5b1c7d3a9f2"  # pragma: allowlist secret
_PARENT = "d4a8f1c2b9e5"  # pragma: allowlist secret
_IDS = ("acb_bex_past", "acb_bex_future", "acb_bex_none")


async def _cleanup(db: DatabaseSession) -> None:
    async with db.transaction() as session:
        await session.execute(
            text("DELETE FROM agent_credential_bindings WHERE id LIKE 'acb_bex_%'")
        )


@pytest.fixture()
async def restore_head(
    integration_config: AppConfig, admin_db: DatabaseSession
) -> AsyncGenerator[None, None]:
    await _cleanup(admin_db)
    yield
    cfg = alembic_config_for("admin", integration_config.databases.admin)
    await asyncio.to_thread(command.upgrade, cfg, "head")
    await _cleanup(admin_db)


async def _has_expires_at(db: DatabaseSession) -> bool:
    async with db.session() as session:
        conn = await session.connection()
        columns = await conn.run_sync(
            lambda c: {col["name"] for col in inspect(c).get_columns("agent_credential_bindings")}
        )
    return "expires_at" in columns


async def test_downgrade_suspends_lapsed_bindings_and_reupgrade_restores_column(
    integration_config: AppConfig, admin_db: DatabaseSession, restore_head: None
) -> None:
    cfg = alembic_config_for("admin", integration_config.databases.admin)
    now = datetime.now(UTC)
    rows = {
        "acb_bex_past": now - timedelta(days=1),
        "acb_bex_future": now + timedelta(days=1),
        "acb_bex_none": None,
    }
    async with admin_db.transaction() as session:
        for binding_id, expires_at in rows.items():
            await session.execute(
                text(
                    "INSERT INTO agent_credential_bindings "
                    "(id, agent_id, credential_id, suspended, expires_at) "
                    "VALUES (:id, :agent, :cred, :suspended, :expires_at)"
                ),
                {
                    "id": binding_id,
                    "agent": f"agnt_{binding_id}",
                    "cred": f"cred_{binding_id}",
                    "suspended": False,
                    "expires_at": expires_at,
                },
            )

    await asyncio.to_thread(command.downgrade, cfg, _PARENT)
    assert not await _has_expires_at(admin_db)
    async with admin_db.session() as session:
        result = await session.execute(
            text(
                "SELECT id, suspended, suspended_reason FROM agent_credential_bindings "
                "WHERE id LIKE 'acb_bex_%'"
            )
        )
        state = {r[0]: (bool(r[1]), r[2]) for r in result.all()}
    assert state["acb_bex_past"] == (True, "binding_expired")
    assert state["acb_bex_future"] == (False, None)
    assert state["acb_bex_none"] == (False, None)

    await asyncio.to_thread(command.upgrade, cfg, _REVISION)
    assert await _has_expires_at(admin_db)
    async with admin_db.session() as session:
        remaining = (
            await session.execute(
                text(
                    "SELECT count(*) FROM agent_credential_bindings "
                    "WHERE id LIKE 'acb_bex_%' AND expires_at IS NOT NULL"
                )
            )
        ).scalar_one()
    assert remaining == 0


@pytest.mark.parametrize("starting_head", ["f6a2c8d4e1b7", _PARENT])  # pragma: allowlist secret
async def test_upgrade_from_independent_branch(
    integration_config: AppConfig, admin_db: DatabaseSession, restore_head: None, starting_head: str
) -> None:
    cfg = alembic_config_for("admin", integration_config.databases.admin)
    await asyncio.to_thread(command.downgrade, cfg, "c7d2e9a41b30")  # pragma: allowlist secret
    await asyncio.to_thread(command.upgrade, cfg, starting_head)
    await asyncio.to_thread(command.upgrade, cfg, "head")
    assert await _has_expires_at(admin_db)
    async with admin_db.session() as session:
        await session.execute(text("SELECT expires_at FROM agents LIMIT 0"))
        conn = await session.connection()
        indexes = await conn.run_sync(lambda c: inspect(c).get_indexes("execution_records"))
        assert "ix_execution_records_actor_credential_last_used" in {idx["name"] for idx in indexes}
