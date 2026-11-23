"""Daily job that warns an agent's owner before a binding's idle limit is reached.

Only bindings whose owner turned the warning on (``idle_warning``) are
considered, and only idle limits long enough for a warning to mean something
(4 days by default). A binding whose idle deadline falls within the window (48
hours by default) gets one ``credential_grant.idle_expiring`` event, with
``requires_action``, addressed to the agent's owner. ``idle_warned_at`` marks
it, with a conditional UPDATE, so each idle period warns at most once even with
several replicas running the job; a use or a renewal clears the marker.

Nothing here enforces expiry: a binding the job misses still ends on time,
because the broker checks the policy whenever it reads the binding.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, ClassVar

import structlog
from sqlalchemy import text

from jentic_one.shared.auth.grant_policy import (
    GRANT_POLICY_COLUMNS,
    GrantPolicy,
    idle_warning_due,
)
from jentic_one.shared.config import GrantExpiryConfig
from jentic_one.shared.events import emit_event, summary_label
from jentic_one.shared.jobs.periodic import PeriodicScanner
from jentic_one.shared.models.events import EventSeverity, EventType

if TYPE_CHECKING:
    from jentic_one.shared.db.session import DatabaseSession

logger = structlog.get_logger(__name__)

_CANDIDATES = text(
    "SELECT b.id, b.agent_id, b.credential_id, a.name AS agent_name, "
    f"{', '.join('b.' + c.strip() for c in GRANT_POLICY_COLUMNS.split(','))} "
    "FROM agent_credential_bindings b LEFT JOIN agents a ON a.id = b.agent_id "
    "WHERE b.idle_warning = true AND b.suspended = false "
    "AND b.idle_warned_at IS NULL AND b.max_idle_period >= :min_idle"
)

_MARK = text(
    "UPDATE agent_credential_bindings SET idle_warned_at = :now "
    "WHERE id = :id AND idle_warned_at IS NULL"
)


class BindingIdleWarningScanner(PeriodicScanner):
    """Warns owners, once per idle period, before an opted-in binding goes idle."""

    name: ClassVar[str] = "binding_idle_warning_scanner"

    def __init__(
        self, admin_db: DatabaseSession, *, config: GrantExpiryConfig | None = None
    ) -> None:
        self._admin_db = admin_db
        self._config = config or GrantExpiryConfig()
        self._poll_interval = float(self._config.idle_warning_interval_s)
        self._running = False

    async def _tick(self) -> None:
        await self.sweep()

    async def sweep(self, *, now: datetime | None = None) -> int:
        """Warn about every binding due a warning; return how many events were emitted."""
        now = now or datetime.now(UTC)
        window = timedelta(hours=self._config.idle_warning_window_h)
        min_idle = self._config.idle_warning_min_idle_days * 86_400
        async with self._admin_db.read_session() as session:
            rows = (await session.execute(_CANDIDATES, {"min_idle": min_idle})).all()
        emitted = 0
        for row in rows:
            deadline = idle_warning_due(
                GrantPolicy.from_row(row), now=now, window=window, min_idle_period=min_idle
            )
            if deadline is None:
                continue
            try:
                async with self._admin_db.transaction() as session:
                    marked = await session.execute(_MARK, {"now": now, "id": row.id})
                    if not getattr(marked, "rowcount", 0):
                        continue  # another replica warned first
                    await emit_event(
                        session,
                        type=EventType.CREDENTIAL_GRANT_IDLE_EXPIRING,
                        severity=EventSeverity.WARNING,
                        summary=(
                            f"Agent {summary_label(row.agent_name, row.agent_id)}'s access to "
                            f"credential {row.credential_id} ends if unused before "
                            f"{deadline.strftime('%Y-%m-%d %H:%M UTC')}"
                        ),
                        # Binding events are the agent's, so its owner sees them.
                        created_by=row.agent_id,
                        requires_action=True,
                        data={
                            "agent_id": row.agent_id,
                            "credential_id": row.credential_id,
                            "idle_expires_at": deadline.isoformat(),
                            "max_idle_period": row.max_idle_period,
                        },
                    )
                emitted += 1
            except Exception:
                # The marker rolled back with the event, so it is retried next run.
                logger.warning(
                    "binding_idle_warning_failed",
                    agent_id=row.agent_id,
                    credential_id=row.credential_id,
                )
        if emitted:
            logger.info("binding_idle_warnings_emitted", count=emitted)
        return emitted
