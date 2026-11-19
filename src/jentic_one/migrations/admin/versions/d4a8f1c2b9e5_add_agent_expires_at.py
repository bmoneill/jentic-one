"""add expires_at to agents

Adds a nullable ``expires_at`` timestamp to ``agents``. An agent whose
``expires_at`` has passed is refused new tokens and its issued tokens stop
resolving as active. Existing rows stay ``NULL`` (never expires); no backfill
or index is required.

The downgrade first disables every active agent whose expiry has already
passed, so rolling the code back fails closed instead of reviving a lapsed
agent, and only then drops the column. An operator restores such an agent with
``:enable``.

Revision ID: d4a8f1c2b9e5
Revises: c7d2e9a41b30
Create Date: 2026-11-18

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "d4a8f1c2b9e5"  # pragma: allowlist secret
down_revision: str | None = "c7d2e9a41b30"  # pragma: allowlist secret
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # An earlier stacked build applied this column before stamping the
    # independent last-use revision. Such a database already has the column.
    if any(col["name"] == "expires_at" for col in sa.inspect(op.get_bind()).get_columns("agents")):
        return
    op.add_column("agents", sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    agents = sa.table(
        "agents",
        sa.column("expires_at", sa.DateTime(timezone=True)),
        sa.column("status", sa.String),
    )
    op.execute(
        agents.update()
        .where(agents.c.status == "active")
        .where(agents.c.expires_at.is_not(None))
        .where(agents.c.expires_at <= sa.func.now())
        .values(status="disabled")
    )
    op.drop_column("agents", "expires_at")
