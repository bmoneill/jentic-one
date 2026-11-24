"""add a kind to held_executions

Adds ``kind`` (``execution`` or ``grant_renewal``, default ``execution``) to
``held_executions``. A ``grant_renewal`` hold is filed when an agent calls
through a binding that has ended: its owner can re-grant the binding
and run the call. Every existing hold is an ``execution`` hold.

A partial unique index keeps one pending renewal per binding
(``agent_id``, ``credential_id``).

The downgrade drops both. A pending renewal left behind reads as an ordinary
held call; approving it runs the call into the still-ended binding, which the
run-time re-authorization refuses, so it fails closed.

Revision ID: d0f6b2c4e5a7
Revises: c9e5a1b3d4f6
Create Date: 2026-11-23

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "d0f6b2c4e5a7"  # pragma: allowlist secret
down_revision: str | None = "c9e5a1b3d4f6"  # pragma: allowlist secret
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_PENDING_RENEWAL = "state = 'pending' AND kind = 'grant_renewal'"


def upgrade() -> None:
    bind = op.get_bind()
    existing = {col["name"] for col in sa.inspect(bind).get_columns("held_executions")}
    if "kind" not in existing:
        op.add_column(
            "held_executions",
            sa.Column("kind", sa.String(16), nullable=False, server_default=sa.text("'execution'")),
        )
    indexes = {ix["name"] for ix in sa.inspect(bind).get_indexes("held_executions")}
    if "uq_held_executions_pending_renewal" not in indexes:
        op.create_index(
            "uq_held_executions_pending_renewal",
            "held_executions",
            ["agent_id", "credential_id"],
            unique=True,
            postgresql_where=sa.text(_PENDING_RENEWAL),
            sqlite_where=sa.text(_PENDING_RENEWAL),
        )


def downgrade() -> None:
    op.drop_index("uq_held_executions_pending_renewal", table_name="held_executions")
    op.drop_column("held_executions", "kind")
