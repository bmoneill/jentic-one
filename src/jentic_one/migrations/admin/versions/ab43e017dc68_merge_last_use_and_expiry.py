"""Merge independently deployable last-use and expiry revisions."""

from collections.abc import Sequence

revision = "ab43e017dc68"  # pragma: allowlist secret
down_revision = ("e5b1c7d3a9f2", "f6a2c8d4e1b7")  # pragma: allowlist secret
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
