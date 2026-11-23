"""Record that an agent used a credential binding (admin DB, raw SQL).

The broker may not import the admin ORM, so like the binding resolver this
runs as raw SQL. ``last_used_at`` restarts a binding's idle clock; it is
written at most once per interval (an hour by default), so tracking use
never turns every broker call into a row write.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

_RECORD_USE = text(
    # A use also clears the idle warning's marker: the next idle period may warn again.
    "UPDATE agent_credential_bindings SET last_used_at = :now, idle_warned_at = NULL "
    "WHERE agent_id = :agent_id AND credential_id = :credential_id "
    "AND (last_used_at IS NULL OR last_used_at <= :stale_before)"
)


class BindingUseRepository:
    """Flush-only writes of a binding's use; the caller owns the transaction."""

    @staticmethod
    async def record_use(
        session: AsyncSession,
        *,
        agent_id: str,
        credential_id: str,
        now: datetime,
        min_interval: timedelta,
    ) -> bool:
        """Stamp ``last_used_at = now`` unless it was stamped within ``min_interval``.

        Returns whether a row changed. A binding the agent no longer holds
        (or a caller that is not an agent) changes nothing.
        """
        result = await session.execute(
            _RECORD_USE,
            {
                "now": now,
                "agent_id": agent_id,
                "credential_id": credential_id,
                "stale_before": now - min_interval,
            },
        )
        return bool(getattr(result, "rowcount", 0))
