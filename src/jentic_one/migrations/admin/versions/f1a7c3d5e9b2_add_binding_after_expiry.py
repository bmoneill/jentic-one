"""add after_expiry and the end-date warning marker to agent_credential_bindings

Adds ``after_expiry`` (``hold`` or ``refuse``, default ``hold``): what the
broker does with a call through a binding that has ended. ``hold`` keeps the
first such call for the owner to renew and run; ``refuse`` answers a plain
``403 credential_binding_expired``, telling the agent to ask its owner. Every
existing binding gets ``hold``, as before.

Adds ``expiry_warned_at`` (nullable): the warning (``idle_warning``) now also
covers an approaching end date, and this marks that the end-date warning was
sent, so each end date warns once. A renewal clears it.

Neither column grants access, so the downgrade only drops them (an older
release then holds every ended binding's first call, as it always did).

Revision ID: f1a7c3d5e9b2
Revises: d0f6b2c4e5a7
Create Date: 2026-11-24

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "f1a7c3d5e9b2"  # pragma: allowlist secret
down_revision: str | None = "d0f6b2c4e5a7"  # pragma: allowlist secret
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    existing = {
        col["name"] for col in sa.inspect(op.get_bind()).get_columns("agent_credential_bindings")
    }
    if "after_expiry" not in existing:
        op.add_column(
            "agent_credential_bindings",
            sa.Column(
                "after_expiry", sa.String(16), nullable=False, server_default=sa.text("'hold'")
            ),
        )
    if "expiry_warned_at" not in existing:
        op.add_column(
            "agent_credential_bindings",
            sa.Column("expiry_warned_at", sa.DateTime(timezone=True), nullable=True),
        )


def downgrade() -> None:
    op.drop_column("agent_credential_bindings", "expiry_warned_at")
    op.drop_column("agent_credential_bindings", "after_expiry")
