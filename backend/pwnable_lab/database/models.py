"""ORM 모델."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class BinaryRecord(Base):
    __tablename__ = "binaries"

    sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    filename: Mapped[str] = mapped_column(String(255))
    size: Mapped[int] = mapped_column(Integer)
    artifact_format: Mapped[str] = mapped_column(String(16), default="ELF")
    machine: Mapped[str] = mapped_column(String(32), default="")
    bits: Mapped[int] = mapped_column(Integer, default=0)
    analysis_status: Mapped[str] = mapped_column(String(16), default="not_started")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=_utcnow, onupdate=_utcnow
    )


class AnalysisJobRecord(Base):
    __tablename__ = "analysis_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    binary_sha256: Mapped[str] = mapped_column(
        ForeignKey("binaries.sha256", ondelete="CASCADE"), index=True
    )
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)
    analyzer_name: Mapped[str] = mapped_column(String(64), default="phase1_metadata")
    analyzer_version: Mapped[str] = mapped_column(String(32), default="1.0.0")
    confidence: Mapped[float] = mapped_column(default=1.0)
    evidence: Mapped[list] = mapped_column(JSON, default=list)
    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=_utcnow, onupdate=_utcnow
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class AuditLogRecord(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    resource_type: Mapped[str] = mapped_column(String(32))
    resource_id: Mapped[str] = mapped_column(String(128), index=True)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class SubmissionRecord(Base):
    __tablename__ = "submissions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    slug: Mapped[str] = mapped_column(String(64), index=True)
    correct: Mapped[int] = mapped_column(Integer, default=0)  # 0/1
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class CrashArtifactRecord(Base):
    """A bounded textual debugger log; never an executable artifact."""

    __tablename__ = "crash_artifacts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    filename: Mapped[str] = mapped_column(String(255))
    size: Mapped[int] = mapped_column(Integer)
    binary_sha256: Mapped[str | None] = mapped_column(
        ForeignKey("binaries.sha256", ondelete="SET NULL"), nullable=True, index=True
    )
    log_text: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class CrashAnalysisRecord(Base):
    __tablename__ = "crash_analyses"

    crash_id: Mapped[str] = mapped_column(
        ForeignKey("crash_artifacts.id", ondelete="CASCADE"), primary_key=True
    )
    analyzer_name: Mapped[str] = mapped_column(String(64))
    analyzer_version: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(32), index=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    confidence: Mapped[float] = mapped_column(default=0.0)
    evidence: Mapped[list] = mapped_column(JSON, default=list)
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=_utcnow, onupdate=_utcnow
    )
