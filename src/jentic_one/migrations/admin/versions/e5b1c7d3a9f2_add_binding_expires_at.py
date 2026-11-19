"""add expires_at to agent_credential_bindings

Adds a nullable ``expires_at`` to ``agent_credential_bindings``. A binding whose
``expires_at`` has passed no longer authorizes broker calls. Existing rows stay
``NULL`` (never expires); no backfill.

The downgrade first suspends every binding whose expiry has already passed
(reason ``binding_expired``), so rolling the code back fails closed instead of
reviving lapsed access, and only then drops the column.

Revision ID: e5b1c7d3a9f2
Revises: d4a8f1c2b9e5
Create Date: 2026-11-18

"""

from collections.abc import Sequence

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


def downgrade() -> None:
    bindings = sa.table(
        "agent_credential_bindings",
        sa.column("expires_at", sa.DateTime(timezone=True)),
        sa.column("suspended", sa.Boolean),
        sa.column("suspended_reason", sa.String),
    )
    op.execute(
        bindings.update()
        .where(bindings.c.expires_at.is_not(None))
        .where(bindings.c.expires_at <= sa.func.now())
        .values(suspended=True, suspended_reason="binding_expired")
    )
    op.drop_column("agent_credential_bindings", "expires_at")
