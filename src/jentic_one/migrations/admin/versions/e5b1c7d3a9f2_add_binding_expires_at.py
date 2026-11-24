"""add expires_at to agent_credential_bindings

Adds a nullable ``expires_at`` to ``agent_credential_bindings``. A binding whose
``expires_at`` has passed no longer authorizes broker calls. Existing rows stay
``NULL`` (never expires); no backfill.

The downgrade fails closed: without the column every end date would be
forgotten, so it suspends every binding that has one before dropping it.
One whose end date has passed is suspended as ``binding_expired``; one still
running as ``binding_policy_removed``, so an operator resumes it knowingly
(the older code has no end dates). An already-suspended binding whose end date
has passed is relabelled ``binding_expired``, so nobody resumes it thinking
only the earlier suspension applies.

Revision ID: e5b1c7d3a9f2
Revises: d4a8f1c2b9e5
Create Date: 2026-11-18

"""

from collections.abc import Sequence
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision: str = "e5b1c7d3a9f2"  # pragma: allowlist secret
down_revision: str | None = "d4a8f1c2b9e5"  # pragma: allowlist secret
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # An earlier stacked build ran this revision before the last-use index
    # (f6a2c8d4e1b7) and stopped at that index, so it already has the column.
    if any(
        col["name"] == "expires_at"
        for col in sa.inspect(op.get_bind()).get_columns("agent_credential_bindings")
    ):
        return
    op.add_column(
        "agent_credential_bindings",
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
    )


_BINDINGS = sa.table(
    "agent_credential_bindings",
    sa.column("id", sa.String),
    sa.column("expires_at", sa.DateTime(timezone=True)),
    sa.column("suspended", sa.Boolean),
    sa.column("suspended_reason", sa.String),
)


def _as_utc(value: datetime | str) -> datetime:
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def downgrade() -> None:
    conn = op.get_bind()
    now = datetime.now(UTC)
    # Compared in Python: SQLite stores the values as text, with their offsets.
    rows = conn.execute(
        sa.select(_BINDINGS.c.id, _BINDINGS.c.expires_at, _BINDINGS.c.suspended).where(
            _BINDINGS.c.expires_at.is_not(None)
        )
    ).all()
    ended = {row.id for row in rows if _as_utc(row.expires_at) <= now}
    for ids, values in (
        (ended, {"suspended": True, "suspended_reason": "binding_expired"}),
        (
            {row.id for row in rows if not row.suspended} - ended,
            {"suspended": True, "suspended_reason": "binding_policy_removed"},
        ),
    ):
        if ids:
            conn.execute(_BINDINGS.update().where(_BINDINGS.c.id.in_(sorted(ids))).values(**values))
    op.drop_column("agent_credential_bindings", "expires_at")
