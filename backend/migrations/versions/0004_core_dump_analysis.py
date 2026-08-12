"""Allow persisted Linux ELF core artifacts.

Revision ID: 0004_core_dumps
Revises: 0003_crash_logs
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004_core_dumps"
down_revision: str | None = "0003_crash_logs"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    columns = {column["name"] for column in inspector.get_columns("crash_artifacts")}
    with op.batch_alter_table("crash_artifacts") as batch:
        if "artifact_kind" not in columns:
            batch.add_column(
                sa.Column(
                    "artifact_kind",
                    sa.String(length=16),
                    nullable=False,
                    server_default="text_log",
                )
            )
        batch.alter_column(
            "log_text",
            existing_type=sa.Text(),
            nullable=True,
        )


def downgrade() -> None:
    connection = op.get_bind()
    connection.execute(
        sa.text(
            "DELETE FROM crash_analyses WHERE crash_id IN "
            "(SELECT id FROM crash_artifacts WHERE artifact_kind = 'core_dump')"
        )
    )
    connection.execute(
        sa.text("DELETE FROM crash_artifacts WHERE artifact_kind = 'core_dump'")
    )
    with op.batch_alter_table("crash_artifacts") as batch:
        batch.alter_column(
            "log_text",
            existing_type=sa.Text(),
            nullable=False,
        )
        batch.drop_column("artifact_kind")
