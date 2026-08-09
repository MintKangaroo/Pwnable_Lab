"""Add bounded text crash artifacts and analysis results.

Revision ID: 0003_crash_logs
Revises: 0002_artifact_format
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_crash_logs"
down_revision: str | None = "0002_artifact_format"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    tables = set(inspector.get_table_names())
    if "crash_artifacts" not in tables:
        op.create_table(
            "crash_artifacts",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("sha256", sa.String(length=64), nullable=False),
            sa.Column("filename", sa.String(length=255), nullable=False),
            sa.Column("size", sa.Integer(), nullable=False),
            sa.Column(
                "binary_sha256",
                sa.String(length=64),
                sa.ForeignKey("binaries.sha256", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("log_text", sa.Text(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
        )
        op.create_index("ix_crash_artifacts_sha256", "crash_artifacts", ["sha256"])
        op.create_index(
            "ix_crash_artifacts_binary_sha256", "crash_artifacts", ["binary_sha256"]
        )
    if "crash_analyses" not in tables:
        op.create_table(
            "crash_analyses",
            sa.Column(
                "crash_id",
                sa.String(length=36),
                sa.ForeignKey("crash_artifacts.id", ondelete="CASCADE"),
                primary_key=True,
            ),
            sa.Column("analyzer_name", sa.String(length=64), nullable=False),
            sa.Column("analyzer_version", sa.String(length=32), nullable=False),
            sa.Column("status", sa.String(length=32), nullable=False),
            sa.Column("error", sa.Text(), nullable=True),
            sa.Column("confidence", sa.Float(), nullable=False),
            sa.Column("evidence", sa.JSON(), nullable=False),
            sa.Column("result", sa.JSON(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
        )
        op.create_index("ix_crash_analyses_status", "crash_analyses", ["status"])


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    tables = set(inspector.get_table_names())
    if "crash_analyses" in tables:
        op.drop_index("ix_crash_analyses_status", table_name="crash_analyses")
        op.drop_table("crash_analyses")
    if "crash_artifacts" in tables:
        op.drop_index("ix_crash_artifacts_binary_sha256", table_name="crash_artifacts")
        op.drop_index("ix_crash_artifacts_sha256", table_name="crash_artifacts")
        op.drop_table("crash_artifacts")
