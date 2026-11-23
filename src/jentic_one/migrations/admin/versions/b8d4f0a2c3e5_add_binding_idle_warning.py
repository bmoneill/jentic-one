"""add the idle warning to agent_credential_bindings

Adds ``idle_warning`` (boolean, default false) and ``idle_warned_at``
(nullable) to ``agent_credential_bindings``. With ``idle_warning`` on, a daily
job tells the agent's owner when the binding will reach its idle limit within
48 hours; ``idle_warned_at`` marks that it did, so each idle period warns once.
Every existing binding gets the warning off. Neither column ends access, so
the downgrade only drops them.

Revision ID: b8d4f0a2c3e5
Revises: a7c3e9f1b2d4
Create Date: 2026-11-23

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "b8d4f0a2c3e5"  # pragma: allowlist secret
down_revision: str | None = "a7c3e9f1b2d4"  # pragma: allowlist secret
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    existing = {
        col["name"] for col in sa.inspect(op.get_bind()).get_columns("agent_credential_bindings")
    }
    if "idle_warning" not in existing:
        op.add_column(
            "agent_credential_bindings",
            sa.Column(
                "idle_warning", sa.Boolean(), nullable=False, server_default=sa.text("false")
            ),
        )
    if "idle_warned_at" not in existing:
        op.add_column(
            "agent_credential_bindings",
            sa.Column("idle_warned_at", sa.DateTime(timezone=True), nullable=True),
        )


def downgrade() -> None:
    op.drop_column("agent_credential_bindings", "idle_warned_at")
    op.drop_column("agent_credential_bindings", "idle_warning")
