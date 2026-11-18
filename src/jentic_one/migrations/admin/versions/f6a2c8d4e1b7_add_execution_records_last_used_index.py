"""add ix_execution_records_actor_credential_last_used

"Last used" for an agent's credential bindings is the latest
``execution_records.started_at`` per agent, credential and API
(``ExecutionRecordRepository.last_used_by_api``, and
``PrerequisiteRepository.last_used_by_agents`` for a credential's agents). It
is read on every agent bindings list, bind, resume and renew, and every
credential agent list. The existing indexes are on ``(actor_id, actor_type)``
and ``credential_id`` alone, so each read fetched every one of the agent's
executions from the heap. This index leads with the two equality columns and
carries the grouping columns and ``started_at``, so both reads are answered
from the index alone.

Built ``CONCURRENTLY`` in an autocommit block on PostgreSQL so the migration
never holds a write-blocking lock on ``execution_records``. A failed
concurrent build leaves an INVALID index of the same name behind, so
``upgrade()`` first drops any INVALID leftover before ``CREATE INDEX
CONCURRENTLY IF NOT EXISTS``. On SQLite the concurrency flag is ignored.

Revision ID: f6a2c8d4e1b7
Revises: e5b1c7d3a9f2
Create Date: 2026-11-18

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "f6a2c8d4e1b7"  # pragma: allowlist secret
down_revision: str | None = "e5b1c7d3a9f2"  # pragma: allowlist secret
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "execution_records"
_INDEX = "ix_execution_records_actor_credential_last_used"


def _drop_invalid_leftover(index_name: str) -> None:
    """Drop ``index_name`` if a failed concurrent build left it INVALID (PostgreSQL only)."""
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    invalid = bind.execute(
        sa.text(
            "SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid "
            "WHERE c.relname = :name AND c.relnamespace = to_regnamespace(current_schema()) "
            "AND NOT i.indisvalid"
        ),
        {"name": index_name},
    ).scalar()
    if invalid:
        op.drop_index(index_name, table_name=_TABLE, postgresql_concurrently=True, if_exists=True)


def upgrade() -> None:
    with op.get_context().autocommit_block():
        _drop_invalid_leftover(_INDEX)
        op.create_index(
            _INDEX,
            _TABLE,
            ["actor_id", "credential_id", "api_vendor", "api_name", "started_at"],
            unique=False,
            postgresql_concurrently=True,
            if_not_exists=True,
        )


def downgrade() -> None:
    with op.get_context().autocommit_block():
        op.drop_index(_INDEX, table_name=_TABLE, postgresql_concurrently=True, if_exists=True)
