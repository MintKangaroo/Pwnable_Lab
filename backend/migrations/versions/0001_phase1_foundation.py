"""Phase 1 artifact, analysis job, and audit schema.

Revision ID: 0001_phase1
Revises:
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001_phase1"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    if "binaries" not in tables:
        op.create_table(
            "binaries",
            sa.Column("sha256", sa.String(length=64), primary_key=True),
            sa.Column("filename", sa.String(length=255), nullable=False),
            sa.Column("size", sa.Integer(), nullable=False),
            sa.Column("machine", sa.String(length=32), nullable=False),
            sa.Column("bits", sa.Integer(), nullable=False),
            sa.Column(
                "analysis_status",
                sa.String(length=16),
                nullable=False,
                server_default="not_started",
            ),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
        )
    else:
        columns = {column["name"] for column in inspector.get_columns("binaries")}
        with op.batch_alter_table("binaries") as batch:
            if "analysis_status" not in columns:
                batch.add_column(
                    sa.Column(
                        "analysis_status",
                        sa.String(length=16),
                        nullable=False,
                        server_default="not_started",
                    )
                )
            if "updated_at" not in columns:
                batch.add_column(
                    sa.Column(
                        "updated_at",
                        sa.DateTime(),
                        nullable=True,
                    )
                )
        if "updated_at" not in columns:
            op.execute("UPDATE binaries SET updated_at = created_at")
            with op.batch_alter_table("binaries") as batch:
                batch.alter_column(
                    "updated_at",
                    existing_type=sa.DateTime(),
                    nullable=False,
                )

    if "submissions" not in tables:
        op.create_table(
            "submissions",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("slug", sa.String(length=64), nullable=False),
            sa.Column("correct", sa.Integer(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
        )
        op.create_index("ix_submissions_slug", "submissions", ["slug"])

    if "analysis_jobs" not in tables:
        op.create_table(
            "analysis_jobs",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column(
                "binary_sha256",
                sa.String(length=64),
                sa.ForeignKey("binaries.sha256", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "status",
                sa.String(length=16),
                nullable=False,
                server_default="queued",
            ),
            sa.Column("analyzer_name", sa.String(length=64), nullable=False),
            sa.Column("analyzer_version", sa.String(length=32), nullable=False),
            sa.Column("confidence", sa.Float(), nullable=False),
            sa.Column("evidence", sa.JSON(), nullable=False),
            sa.Column("result", sa.JSON(), nullable=True),
            sa.Column("error", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.Column("completed_at", sa.DateTime(), nullable=True),
        )
        op.create_index(
            "ix_analysis_jobs_binary_sha256",
            "analysis_jobs",
            ["binary_sha256"],
        )
        op.create_index("ix_analysis_jobs_status", "analysis_jobs", ["status"])

    if "audit_logs" not in tables:
        op.create_table(
            "audit_logs",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("action", sa.String(length=64), nullable=False),
            sa.Column("resource_type", sa.String(length=32), nullable=False),
            sa.Column("resource_id", sa.String(length=128), nullable=False),
            sa.Column("detail", sa.JSON(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
        )
        op.create_index("ix_audit_logs_action", "audit_logs", ["action"])
        op.create_index("ix_audit_logs_resource_id", "audit_logs", ["resource_id"])


def downgrade() -> None:
    op.drop_index("ix_audit_logs_resource_id", table_name="audit_logs")
    op.drop_index("ix_audit_logs_action", table_name="audit_logs")
    op.drop_table("audit_logs")
    op.drop_index("ix_analysis_jobs_status", table_name="analysis_jobs")
    op.drop_index("ix_analysis_jobs_binary_sha256", table_name="analysis_jobs")
    op.drop_table("analysis_jobs")
    with op.batch_alter_table("binaries") as batch:
        batch.drop_column("updated_at")
        batch.drop_column("analysis_status")
