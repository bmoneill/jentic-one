"""Repository for AgentCredentialBinding CRUD."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from jentic_one.admin.core.schema.agent_credential_bindings import AgentCredentialBinding
from jentic_one.shared.db.locks import lock_agent_bindings, lock_credential_bindings


class AgentCredentialBindingRepository:
    """Data access layer for AgentCredentialBinding entities — flush-only, never commits."""

    @staticmethod
    async def bind(
        session: AsyncSession,
        *,
        agent_id: str,
        credential_id: str,
        created_by: str,
        expires_at: datetime | None = None,
        max_idle_period: int | None = None,
    ) -> AgentCredentialBinding:
        await lock_agent_bindings(session, agent_id)
        await lock_credential_bindings(session, credential_id)
        binding = AgentCredentialBinding(
            agent_id=agent_id,
            credential_id=credential_id,
            created_by=created_by,
            expires_at=expires_at,
            max_idle_period=max_idle_period,
            # Granting starts the idle clock.
            renewed_at=datetime.now(UTC),
        )
        session.add(binding)
        await session.flush()
        return binding

    @staticmethod
    async def get(
        session: AsyncSession, *, agent_id: str, credential_id: str
    ) -> AgentCredentialBinding | None:
        stmt = (
            select(AgentCredentialBinding)
            .where(AgentCredentialBinding.agent_id == agent_id)
            .where(AgentCredentialBinding.credential_id == credential_id)
        )
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    @staticmethod
    async def set_suspended(
        session: AsyncSession, *, agent_id: str, credential_id: str, suspended: bool
    ) -> bool:
        """Flip the reversible cut-off flag; returns False when no binding exists.

        Resuming clears ``suspended_reason`` (it lifts whatever suspension was
        in place). Suspending leaves it alone: an active binding never carries
        a reason, so a manual suspension stays ``NULL``, and re-suspending a
        binding the registry already suspended keeps its ``api_deleted``
        reason instead of erasing why it stopped working.
        """
        values: dict[str, object] = {"suspended": suspended}
        if not suspended:
            values["suspended_reason"] = None
        stmt = (
            update(AgentCredentialBinding)
            .where(AgentCredentialBinding.agent_id == agent_id)
            .where(AgentCredentialBinding.credential_id == credential_id)
            .values(**values)
        )
        result = await session.execute(stmt)
        await session.flush()
        return int(result.rowcount) > 0  # type: ignore[attr-defined]

    @staticmethod
    async def set_expires_at(
        session: AsyncSession, *, agent_id: str, credential_id: str, expires_at: datetime | None
    ) -> bool:
        """Set, move or clear the fixed expiry; returns False when no binding exists."""
        stmt = (
            update(AgentCredentialBinding)
            .where(AgentCredentialBinding.agent_id == agent_id)
            .where(AgentCredentialBinding.credential_id == credential_id)
            .values(expires_at=expires_at)
        )
        result = await session.execute(stmt)
        await session.flush()
        return int(result.rowcount) > 0  # type: ignore[attr-defined]

    @staticmethod
    async def renew(
        session: AsyncSession,
        *,
        agent_id: str,
        credential_id: str,
        policy: dict[str, Any],
        now: datetime,
    ) -> bool:
        """Re-certify a binding: apply ``policy`` changes and restart its idle clock.

        ``policy`` holds only the policy columns the renewal sets (a key with
        ``None`` clears that limit; an absent key leaves it alone). Every
        renewal sets ``renewed_at = now``. Returns False when no binding exists.
        """
        stmt = (
            update(AgentCredentialBinding)
            .where(AgentCredentialBinding.agent_id == agent_id)
            .where(AgentCredentialBinding.credential_id == credential_id)
            .values(**policy, renewed_at=now)
        )
        result = await session.execute(stmt)
        await session.flush()
        return int(result.rowcount) > 0  # type: ignore[attr-defined]

    @staticmethod
    async def purge(session: AsyncSession, *, agent_id: str, credential_id: str) -> bool:
        """Delete the binding row outright (explicit destructive unbind)."""
        stmt = (
            delete(AgentCredentialBinding)
            .where(AgentCredentialBinding.agent_id == agent_id)
            .where(AgentCredentialBinding.credential_id == credential_id)
        )
        result = await session.execute(stmt)
        await session.flush()
        return int(result.rowcount) > 0  # type: ignore[attr-defined]

    @staticmethod
    async def list_for_agent(session: AsyncSession, agent_id: str) -> list[AgentCredentialBinding]:
        stmt = (
            select(AgentCredentialBinding)
            .where(AgentCredentialBinding.agent_id == agent_id)
            .order_by(AgentCredentialBinding.bound_at.desc())
        )
        result = await session.execute(stmt)
        return list(result.scalars().all())

    @staticmethod
    async def delete_for_agent(session: AsyncSession, agent_id: str) -> int:
        stmt = delete(AgentCredentialBinding).where(AgentCredentialBinding.agent_id == agent_id)
        result = await session.execute(stmt)
        await session.flush()
        return int(result.rowcount)  # type: ignore[attr-defined]
