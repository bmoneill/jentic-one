"""add expires_at to agents

Adds a nullable ``expires_at`` timestamp to ``agents``. An agent whose
``expires_at`` has passed is refused new tokens and its issued tokens stop
resolving as active. Existing rows stay ``NULL`` (never expires); no backfill
or index is required.

The downgrade fails closed: without the column every agent's end date would
be forgotten, so it first disables every active agent with an expiry, passed
or not (an operator restores one knowingly with ``:enable``), and rejects
every pending agent whose expiry has passed, so it cannot be approved under
the older code. A pending agent whose expiry is still ahead stays pending:
approving it is a human decision either way. Then it drops the column.

Revision ID: d4a8f1c2b9e5
Revises: f6a2c8d4e1b7
Create Date: 2026-11-18

"""

from collections.abc import Sequence
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision: str = "d4a8f1c2b9e5"  # pragma: allowlist secret
down_revision: str | None = "f6a2c8d4e1b7"  # pragma: allowlist secret
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # An earlier stacked build ran this revision before the last-use index
    # (f6a2c8d4e1b7) and stopped at that index, so it already has the column.
    if any(col["name"] == "expires_at" for col in sa.inspect(op.get_bind()).get_columns("agents")):
        return
    op.add_column("agents", sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True))


_AGENTS = sa.table(
    "agents",
    sa.column("id", sa.String),
    sa.column("expires_at", sa.DateTime(timezone=True)),
    sa.column("status", sa.String),
)


def _as_utc(value: datetime | str) -> datetime:
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def downgrade() -> None:
    conn = op.get_bind()
    now = datetime.now(UTC)
    rows = conn.execute(
        sa.select(_AGENTS.c.id, _AGENTS.c.status, _AGENTS.c.expires_at).where(
            _AGENTS.c.expires_at.is_not(None), _AGENTS.c.status.in_(("active", "pending"))
        )
    ).all()
    active = sorted(row.id for row in rows if row.status == "active")
    lapsed_pending = sorted(
        row.id for row in rows if row.status == "pending" and _as_utc(row.expires_at) <= now
    )
    for ids, status in ((active, "disabled"), (lapsed_pending, "rejected")):
        if ids:
            conn.execute(_AGENTS.update().where(_AGENTS.c.id.in_(ids)).values(status=status))
    op.drop_column("agents", "expires_at")
