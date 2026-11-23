"""add a use count to agent_credential_bindings

Adds ``max_quota`` and ``quota_remaining`` (both nullable integers) to
``agent_credential_bindings``. A binding with a use count ends once
``quota_remaining`` reaches zero; the broker takes one use per authorized
call, and a renewal restores the count. Single use is ``max_quota = 1``.
Every existing binding gets no count (unlimited uses).

The downgrade fails closed: without the columns, a binding with a use count
would allow unlimited calls, so every one of them (used up or not) is
suspended with ``suspended_reason = 'binding_expired'`` before the columns
are dropped. An operator can resume them.

Revision ID: c9e5a1b3d4f6
Revises: b8d4f0a2c3e5
Create Date: 2026-11-23

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c9e5a1b3d4f6"  # pragma: allowlist secret
down_revision: str | None = "b8d4f0a2c3e5"  # pragma: allowlist secret
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_BINDINGS = sa.table(
    "agent_credential_bindings",
    sa.column("id", sa.String),
    sa.column("suspended", sa.Boolean),
    sa.column("suspended_reason", sa.String),
    sa.column("max_quota", sa.Integer),
)


def upgrade() -> None:
    existing = {
        col["name"] for col in sa.inspect(op.get_bind()).get_columns("agent_credential_bindings")
    }
    for name in ("max_quota", "quota_remaining"):
        if name not in existing:
            op.add_column("agent_credential_bindings", sa.Column(name, sa.Integer(), nullable=True))


def downgrade() -> None:
    op.get_bind().execute(
        _BINDINGS.update()
        .where(_BINDINGS.c.max_quota.is_not(None))
        .where(_BINDINGS.c.suspended.is_(False))
        .values(suspended=True, suspended_reason="binding_expired")
    )
    op.drop_column("agent_credential_bindings", "quota_remaining")
    op.drop_column("agent_credential_bindings", "max_quota")
