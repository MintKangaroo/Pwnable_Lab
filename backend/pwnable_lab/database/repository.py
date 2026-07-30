"""저장소(repository) — 바이너리 바이트는 디스크에, 메타데이터는 DB에.

파일은 항상 콘텐츠 해시(sha256)로 명명한다. 사용자 입력이 파일 경로에 닿지 않으므로
경로 조작이 원천 차단된다.
"""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import unquote

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from pwnable_lab.artifacts.storage import ArtifactStorage, StagedArtifact
from pwnable_lab.database.models import (
    AnalysisJobRecord,
    AuditLogRecord,
    BinaryRecord,
    SubmissionRecord,
)
from pwnable_lab.errors import NotFoundError


@dataclass
class BinaryRepository:
    session_factory: sessionmaker[Session]
    storage_dir: str

    def __post_init__(self) -> None:
        self.storage = ArtifactStorage.from_path(self.storage_dir)

    # --- 바이너리 ---
    def _path(self, sha256: str) -> str:
        # sha256 은 검증된 16진수 문자열이어야 한다.
        if len(sha256) != 64 or any(c not in "0123456789abcdef" for c in sha256):
            raise NotFoundError("잘못된 바이너리 식별자입니다.")
        return os.path.join(self.storage_dir, sha256)

    def store(
        self, data: bytes, filename: str, machine: str, bits: int
    ) -> BinaryRecord:
        staged = self.storage.stage_bytes(data)
        return self.store_staged(staged, filename, machine, bits)

    def store_staged(
        self,
        staged: StagedArtifact,
        filename: str,
        machine: str,
        bits: int,
    ) -> BinaryRecord:
        self.storage.commit(staged)
        decoded_name = unquote(filename, errors="replace")
        safe_name = (
            decoded_name.replace("\\", "/").rsplit("/", 1)[-1].replace("\x00", "")
        )
        safe_name = "".join(c for c in safe_name if c.isprintable())
        safe_name = safe_name[:255] or "binary"
        with self.session_factory() as session:
            existing = session.get(BinaryRecord, staged.sha256)
            if existing:
                return existing
            record = BinaryRecord(
                sha256=staged.sha256,
                filename=safe_name,
                size=staged.size,
                machine=machine,
                bits=bits,
            )
            session.add(record)
            session.add(
                AuditLogRecord(
                    action="binary.uploaded",
                    resource_type="binary",
                    resource_id=staged.sha256,
                    detail={"size": staged.size, "machine": machine, "bits": bits},
                )
            )
            try:
                session.commit()
            except IntegrityError:
                # 동일 SHA가 동시에 등록된 경우 먼저 커밋된 레코드를 재사용한다.
                session.rollback()
                existing = session.get(BinaryRecord, staged.sha256)
                if existing is None:
                    raise
                return existing
            session.refresh(record)
            return record

    def load_bytes(self, sha256: str) -> bytes:
        path = self._path(sha256)
        if not os.path.exists(path):
            raise NotFoundError(f"바이너리를 찾을 수 없습니다: {sha256}")
        with open(path, "rb") as fh:
            return fh.read()

    def get(self, sha256: str) -> BinaryRecord:
        with self.session_factory() as session:
            record = session.get(BinaryRecord, sha256)
            if record is None:
                raise NotFoundError(f"바이너리를 찾을 수 없습니다: {sha256}")
            return record

    def list(self) -> list[BinaryRecord]:
        with self.session_factory() as session:
            return list(
                session.scalars(
                    select(BinaryRecord).order_by(BinaryRecord.created_at.desc())
                )
            )

    def delete(self, sha256: str) -> None:
        path = self._path(sha256)
        with self.session_factory() as session:
            record = session.get(BinaryRecord, sha256)
            if record is None:
                raise NotFoundError(f"바이너리를 찾을 수 없습니다: {sha256}")
            session.execute(
                delete(AnalysisJobRecord).where(
                    AnalysisJobRecord.binary_sha256 == sha256
                )
            )
            session.delete(record)
            session.add(
                AuditLogRecord(
                    action="binary.deleted",
                    resource_type="binary",
                    resource_id=sha256,
                    detail={"filename": record.filename, "size": record.size},
                )
            )
            session.commit()
        # DB 삭제가 성공한 뒤 파일을 지워 실패 시 깨진 DB 참조 대신 orphan만 남긴다.
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass

    # --- 분석 작업 ---
    def create_analysis_job(
        self,
        sha256: str,
        *,
        analyzer_name: str = "phase1_metadata",
        analyzer_version: str = "1.0.0",
    ) -> AnalysisJobRecord:
        with self.session_factory() as session:
            binary = session.get(BinaryRecord, sha256)
            if binary is None:
                raise NotFoundError(f"바이너리를 찾을 수 없습니다: {sha256}")
            binary.analysis_status = "queued"
            job = AnalysisJobRecord(
                id=str(uuid.uuid4()),
                binary_sha256=sha256,
                status="queued",
                analyzer_name=analyzer_name,
                analyzer_version=analyzer_version,
                confidence=1.0,
                evidence=["ELF structure was validated during upload."],
            )
            session.add(job)
            session.add(
                AuditLogRecord(
                    action="analysis.queued",
                    resource_type="analysis_job",
                    resource_id=job.id,
                    detail={"binary_sha256": sha256, "analyzer": analyzer_name},
                )
            )
            session.commit()
            session.refresh(job)
            return job

    def update_analysis_job(
        self,
        job_id: str,
        *,
        status: str,
        result: dict | None = None,
        error: str | None = None,
    ) -> AnalysisJobRecord:
        with self.session_factory() as session:
            job = session.get(AnalysisJobRecord, job_id)
            if job is None:
                raise NotFoundError(f"분석 작업을 찾을 수 없습니다: {job_id}")
            binary = session.get(BinaryRecord, job.binary_sha256)
            job.status = status
            job.result = result
            job.error = error
            job.updated_at = datetime.now(timezone.utc)
            if status in {"completed", "failed"}:
                job.completed_at = datetime.now(timezone.utc)
            if binary is not None:
                binary.analysis_status = status
            session.add(
                AuditLogRecord(
                    action=f"analysis.{status}",
                    resource_type="analysis_job",
                    resource_id=job.id,
                    detail={"binary_sha256": job.binary_sha256},
                )
            )
            session.commit()
            session.refresh(job)
            return job

    def latest_analysis(self, sha256: str) -> AnalysisJobRecord:
        self.get(sha256)
        with self.session_factory() as session:
            job = session.scalar(
                select(AnalysisJobRecord)
                .where(AnalysisJobRecord.binary_sha256 == sha256)
                .order_by(AnalysisJobRecord.created_at.desc())
                .limit(1)
            )
            if job is None:
                raise NotFoundError(f"바이너리에 대한 분석 작업이 없습니다: {sha256}")
            return job

    # --- 제출 기록 ---
    def record_submission(self, slug: str, correct: bool) -> None:
        with self.session_factory() as session:
            session.add(SubmissionRecord(slug=slug, correct=1 if correct else 0))
            session.commit()

    def stats(self, slug: str) -> dict:
        with self.session_factory() as session:
            rows = list(
                session.scalars(
                    select(SubmissionRecord).where(SubmissionRecord.slug == slug)
                )
            )
        total = len(rows)
        solved = sum(r.correct for r in rows)
        return {"attempts": total, "solved": solved}
