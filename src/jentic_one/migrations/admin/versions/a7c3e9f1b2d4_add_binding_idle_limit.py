"""add the idle limit to agent_credential_bindings

Adds three nullable columns to ``agent_credential_bindings``:

- ``max_idle_period``: whole seconds; the binding ends once it has gone this
  long without a use. ``NULL`` (every existing row) means no idle limit.
- ``last_used_at``: when the agent last made a call through the binding,
  written by the broker at most about once an hour. Backfilled from the
  latest ``execution_records.started_at`` for the binding's agent and
  credential, so the idle clock starts from real history; a binding with no
  record stays ``NULL`` ("never used").
- ``renewed_at``: when the binding was granted or last renewed. The idle
  clock runs from the later of this and ``last_used_at``, so a binding that is
  never used ends one idle period after it was granted, and a renewal resets
  the clock without faking a use. Backfilled from ``bound_at``.

No binding gets an idle limit from this migration, so nothing changes for
existing access.

The backfill must not hold the bindings table: adding a column takes an
exclusive lock on it until the migration commits, and the broker reads
bindings on every call. So the latest use of each binding is aggregated
first, in one pass over ``execution_records`` that locks nothing the broker
needs, and only then are the columns added and written by primary key in
short batches.

The downgrade fails closed: it suspends every binding with an idle limit
before dropping the columns, as ``binding_expired`` when the limit has been
reached and ``binding_policy_removed`` otherwise (the older code has no idle
limits, so an operator resumes it knowingly). An already-suspended binding
whose idle limit has been reached is relabelled ``binding_expired``.

Revision ID: a7c3e9f1b2d4
Revises: e5b1c7d3a9f2
Create Date: 2026-11-23

"""

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta

import sqlalchemy as sa
from alembic import op

revision: str = "a7c3e9f1b2d4"  # pragma: allowlist secret
down_revision: str | None = "e5b1c7d3a9f2"  # pragma: allowlist secret
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_BINDINGS = sa.table(
    "agent_credential_bindings",
    sa.column("id", sa.String),
    sa.column("agent_id", sa.String),
    sa.column("credential_id", sa.String),
    sa.column("bound_at", sa.DateTime(timezone=True)),
    sa.column("suspended", sa.Boolean),
    sa.column("suspended_reason", sa.String),
    sa.column("max_idle_period", sa.Integer),
    sa.column("last_used_at", sa.DateTime(timezone=True)),
    sa.column("renewed_at", sa.DateTime(timezone=True)),
)
# Untyped columns for the batched write: each value goes back exactly as the
# aggregate read it, so SQLite keeps the execution record's stored format.
_BACKFILL = sa.table(
    "agent_credential_bindings",
    sa.column("id"),
    sa.column("last_used_at"),
)
_BATCH = 500
_RECORDS = sa.table(
    "execution_records",
    sa.column("actor_id", sa.String),
    sa.column("credential_id", sa.String),
    sa.column("started_at", sa.DateTime(timezone=True)),
)


def upgrade() -> None:
    conn = op.get_bind()
    existing = {col["name"] for col in sa.inspect(conn).get_columns("agent_credential_bindings")}
    last_used: list[dict[str, object]] = []
    if "last_used_at" not in existing:
        # Before the table is locked: one aggregate over the execution records.
        last_used = [
            {"b_id": row[0], "b_last_used": row[1]}
            for row in conn.execute(
                sa.select(_BINDINGS.c.id, sa.func.max(_RECORDS.c.started_at))
                .select_from(
                    _BINDINGS.join(
                        _RECORDS,
                        sa.and_(
                            _RECORDS.c.actor_id == _BINDINGS.c.agent_id,
                            _RECORDS.c.credential_id == _BINDINGS.c.credential_id,
                        ),
                    )
                )
                .group_by(_BINDINGS.c.id)
            )
        ]
    for name, type_ in (
        ("max_idle_period", sa.Integer()),
        ("last_used_at", sa.DateTime(timezone=True)),
        ("renewed_at", sa.DateTime(timezone=True)),
    ):
        if name not in existing:
            op.add_column("agent_credential_bindings", sa.Column(name, type_, nullable=True))
    write = (
        _BACKFILL.update()
        .where(_BACKFILL.c.id == sa.bindparam("b_id"))
        .values(last_used_at=sa.bindparam("b_last_used"))
    )
    for start in range(0, len(last_used), _BATCH):
        conn.execute(write, last_used[start : start + _BATCH])
    if "renewed_at" not in existing:
        op.execute(_BINDINGS.update().values(renewed_at=_BINDINGS.c.bound_at))


def _as_utc(value: datetime | str) -> datetime:
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def downgrade() -> None:
    conn = op.get_bind()
    now = datetime.now(UTC)
    rows = conn.execute(
        sa.select(
            _BINDINGS.c.id,
            _BINDINGS.c.suspended,
            _BINDINGS.c.max_idle_period,
            _BINDINGS.c.last_used_at,
            _BINDINGS.c.renewed_at,
            _BINDINGS.c.bound_at,
        ).where(_BINDINGS.c.max_idle_period.is_not(None))
    ).all()
    ended = {
        row.id
        for row in rows
        if max(
            _as_utc(value)
            for value in (row.last_used_at, row.renewed_at or row.bound_at)
            if value is not None
        )
        + timedelta(seconds=row.max_idle_period)
        <= now
    }
    for ids, values in (
        (ended, {"suspended": True, "suspended_reason": "binding_expired"}),
        (
            {row.id for row in rows if not row.suspended} - ended,
            {"suspended": True, "suspended_reason": "binding_policy_removed"},
        ),
    ):
        if ids:
            conn.execute(_BINDINGS.update().where(_BINDINGS.c.id.in_(sorted(ids))).values(**values))
    op.drop_column("agent_credential_bindings", "renewed_at")
    op.drop_column("agent_credential_bindings", "last_used_at")
    op.drop_column("agent_credential_bindings", "max_idle_period")
