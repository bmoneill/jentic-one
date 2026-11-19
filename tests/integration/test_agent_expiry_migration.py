"""Upgrade/downgrade of the ``agents.expires_at`` migration.

Downgrading drops the column, so it first disables every active agent whose
expiry has already passed: a code rollback must fail closed, never revive a
lapsed agent. Agents with no expiry or a future expiry, and agents that are not
active, are left alone; re-upgrading restores the column with no backfill.
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

_REVISION = "d4a8f1c2b9e5"  # pragma: allowlist secret
_PARENT = "f6a2c8d4e1b7"  # pragma: allowlist secret


async def _cleanup(db: DatabaseSession) -> None:
    async with db.transaction() as session:
        await session.execute(text("DELETE FROM agents WHERE id LIKE 'agnt_aex_%'"))


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
            lambda c: {col["name"] for col in inspect(c).get_columns("agents")}
        )
    return "expires_at" in columns


async def test_downgrade_disables_lapsed_agents_and_reupgrade_restores_column(
    integration_config: AppConfig, admin_db: DatabaseSession, restore_head: None
) -> None:
    cfg = alembic_config_for("admin", integration_config.databases.admin)
    now = datetime.now(UTC)
    rows = {
        "agnt_aex_past": ("active", now - timedelta(days=1)),
        "agnt_aex_future": ("active", now + timedelta(days=1)),
        "agnt_aex_none": ("active", None),
        "agnt_aex_pending_past": ("pending", now - timedelta(days=1)),
    }
    async with admin_db.transaction() as session:
        for agent_id, (status, expires_at) in rows.items():
            await session.execute(
                text(
                    "INSERT INTO agents (id, name, registered_by, status, expires_at) "
                    "VALUES (:id, :name, 'self', :status, :expires_at)"
                ),
                {"id": agent_id, "name": agent_id, "status": status, "expires_at": expires_at},
            )

    await asyncio.to_thread(command.downgrade, cfg, _PARENT)
    assert not await _has_expires_at(admin_db)
    async with admin_db.session() as session:
        result = await session.execute(
            text("SELECT id, status FROM agents WHERE id LIKE 'agnt_aex_%'")
        )
        state = {r[0]: r[1] for r in result.all()}
    assert state == {
        "agnt_aex_past": "disabled",
        "agnt_aex_future": "active",
        "agnt_aex_none": "active",
        "agnt_aex_pending_past": "pending",
    }

    await asyncio.to_thread(command.upgrade, cfg, _REVISION)
    assert await _has_expires_at(admin_db)
    async with admin_db.session() as session:
        remaining = (
            await session.execute(
                text(
                    "SELECT count(*) FROM agents "
                    "WHERE id LIKE 'agnt_aex_%' AND expires_at IS NOT NULL"
                )
            )
        ).scalar_one()
    assert remaining == 0
