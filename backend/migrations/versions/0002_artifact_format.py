"""Add artifact format for ELF, PE, and raw binaries.

Revision ID: 0002_artifact_format
Revises: 0001_phase1
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_artifact_format"
down_revision: str | None = "0001_phase1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    columns = {column["name"] for column in inspector.get_columns("binaries")}
    if "artifact_format" not in columns:
        with op.batch_alter_table("binaries") as batch:
            batch.add_column(
                sa.Column(
                    "artifact_format",
                    sa.String(length=16),
                    nullable=False,
                    server_default="ELF",
                )
            )


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    columns = {column["name"] for column in inspector.get_columns("binaries")}
    if "artifact_format" in columns:
        with op.batch_alter_table("binaries") as batch:
            batch.drop_column("artifact_format")
