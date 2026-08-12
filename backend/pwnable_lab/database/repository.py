"""저장소(repository) — 바이너리 바이트는 디스크에, 메타데이터는 DB에.

파일은 항상 콘텐츠 해시(sha256)로 명명한다. 사용자 입력이 파일 경로에 닿지 않으므로
경로 조작이 원천 차단된다.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import unquote

from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from pwnable_lab.artifacts.storage import ArtifactStorage, StagedArtifact
from pwnable_lab.database.models import (
    AnalysisJobRecord,
    AuditLogRecord,
    BinaryRecord,
    CrashAnalysisRecord,
    CrashArtifactRecord,
    SubmissionRecord,
)
from pwnable_lab.errors import NotFoundError


@dataclass
class BinaryRepository:
    session_factory: sessionmaker[Session]
    storage_dir: str

    def __post_init__(self) -> None:
        self.storage = ArtifactStorage.from_path(self.storage_dir)
        self.crash_storage = ArtifactStorage.from_path(
            os.path.join(self.storage_dir, "crash-artifacts")
        )

    # --- 바이너리 ---
    def _path(self, sha256: str) -> str:
        # sha256 은 검증된 16진수 문자열이어야 한다.
        if len(sha256) != 64 or any(c not in "0123456789abcdef" for c in sha256):
            raise NotFoundError("잘못된 바이너리 식별자입니다.")
        return os.path.join(self.storage_dir, sha256)

    def store(
        self,
        data: bytes,
        filename: str,
        machine: str,
        bits: int,
        artifact_format: str = "ELF",
    ) -> BinaryRecord:
        staged = self.storage.stage_bytes(data)
        return self.store_staged(
            staged, filename, machine, bits, artifact_format=artifact_format
        )

    def store_staged(
        self,
        staged: StagedArtifact,
        filename: str,
        machine: str,
        bits: int,
        artifact_format: str = "ELF",
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
                artifact_format=artifact_format,
                machine=machine,
                bits=bits,
            )
            session.add(record)
            session.add(
                AuditLogRecord(
                    action="binary.uploaded",
                    resource_type="binary",
                    resource_id=staged.sha256,
                    detail={
                        "size": staged.size,
                        "format": artifact_format,
                        "machine": machine,
                        "bits": bits,
                    },
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
            # SQLite development connections do not always enforce ON DELETE; keep
            # crash-log associations consistent across SQLite and PostgreSQL.
            session.execute(
                update(CrashArtifactRecord)
                .where(CrashArtifactRecord.binary_sha256 == sha256)
                .values(binary_sha256=None)
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
        analyzer_name: str = "static_binary",
        analyzer_version: str = "3.0.0",
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
                evidence=[
                    f"{binary.artifact_format} structure or raw-binary policy was validated during upload."
                ],
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

    # --- 크래시 로그와 ELF core ---
    def store_crash_log(
        self, text: str, filename: str, *, binary_sha256: str | None = None
    ) -> CrashArtifactRecord:
        encoded = text.encode("utf-8")
        digest = hashlib.sha256(encoded).hexdigest()
        safe_name = _safe_filename(filename, fallback="crash.log")
        with self.session_factory() as session:
            if (
                binary_sha256 is not None
                and session.get(BinaryRecord, binary_sha256) is None
            ):
                raise NotFoundError(f"바이너리를 찾을 수 없습니다: {binary_sha256}")
            record = CrashArtifactRecord(
                id=str(uuid.uuid4()),
                sha256=digest,
                filename=safe_name,
                size=len(encoded),
                artifact_kind="text_log",
                binary_sha256=binary_sha256,
                log_text=text,
            )
            session.add(record)
            session.add(
                AuditLogRecord(
                    action="crash.uploaded",
                    resource_type="crash_artifact",
                    resource_id=record.id,
                    detail={
                        "sha256": digest,
                        "size": len(encoded),
                        "binary_sha256": binary_sha256,
                        "kind": "text_log",
                    },
                )
            )
            session.commit()
            session.refresh(record)
            return record

    def store_core_dump(
        self, data: bytes, filename: str, *, binary_sha256: str | None = None
    ) -> CrashArtifactRecord:
        staged = self.crash_storage.stage_bytes(data)
        safe_name = _safe_filename(filename, fallback="core")
        try:
            with self.session_factory() as session:
                if (
                    binary_sha256 is not None
                    and session.get(BinaryRecord, binary_sha256) is None
                ):
                    raise NotFoundError(f"바이너리를 찾을 수 없습니다: {binary_sha256}")
                self.crash_storage.commit(staged)
                record = CrashArtifactRecord(
                    id=str(uuid.uuid4()),
                    sha256=staged.sha256,
                    filename=safe_name,
                    size=staged.size,
                    artifact_kind="core_dump",
                    binary_sha256=binary_sha256,
                    log_text=None,
                )
                session.add(record)
                session.add(
                    AuditLogRecord(
                        action="crash.uploaded",
                        resource_type="crash_artifact",
                        resource_id=record.id,
                        detail={
                            "sha256": staged.sha256,
                            "size": staged.size,
                            "binary_sha256": binary_sha256,
                            "kind": "core_dump",
                        },
                    )
                )
                session.commit()
                session.refresh(record)
                return record
        except BaseException:
            self.crash_storage.discard(staged)
            raise

    def load_crash_bytes(self, crash_id: str) -> bytes:
        artifact = self.get_crash(crash_id)
        if artifact.artifact_kind != "core_dump":
            raise NotFoundError(f"core dump artifact가 아닙니다: {crash_id}")
        path = self.crash_storage.path_for(artifact.sha256)
        if not path.is_file():
            raise NotFoundError(f"core dump 파일을 찾을 수 없습니다: {crash_id}")
        return path.read_bytes()

    def save_crash_analysis(self, crash_id: str, result: dict) -> CrashAnalysisRecord:
        now = datetime.now(timezone.utc)
        with self.session_factory() as session:
            artifact = session.get(CrashArtifactRecord, crash_id)
            if artifact is None:
                raise NotFoundError(f"크래시 로그를 찾을 수 없습니다: {crash_id}")
            record = session.get(CrashAnalysisRecord, crash_id)
            if record is None:
                record = CrashAnalysisRecord(
                    crash_id=crash_id,
                    analyzer_name=str(result["analyzer_name"]),
                    analyzer_version=str(result["analyzer_version"]),
                    status=str(result["status"]),
                    error=result.get("error"),
                    confidence=float(result["confidence"]),
                    evidence=list(result.get("evidence", [])),
                    result=result,
                )
                session.add(record)
            else:
                record.analyzer_name = str(result["analyzer_name"])
                record.analyzer_version = str(result["analyzer_version"])
                record.status = str(result["status"])
                record.error = result.get("error")
                record.confidence = float(result["confidence"])
                record.evidence = list(result.get("evidence", []))
                record.result = result
                record.updated_at = now
            session.add(
                AuditLogRecord(
                    action="crash.analyzed",
                    resource_type="crash_artifact",
                    resource_id=crash_id,
                    detail={
                        "status": result["status"],
                        "analyzer": result["analyzer_name"],
                    },
                )
            )
            session.commit()
            session.refresh(record)
            return record

    def get_crash(self, crash_id: str) -> CrashArtifactRecord:
        with self.session_factory() as session:
            record = session.get(CrashArtifactRecord, crash_id)
            if record is None:
                raise NotFoundError(f"크래시 로그를 찾을 수 없습니다: {crash_id}")
            return record

    def get_crash_analysis(self, crash_id: str) -> CrashAnalysisRecord:
        self.get_crash(crash_id)
        with self.session_factory() as session:
            record = session.get(CrashAnalysisRecord, crash_id)
            if record is None:
                raise NotFoundError(f"크래시 분석 결과가 없습니다: {crash_id}")
            return record

    def list_crashes(
        self,
    ) -> Sequence[tuple[CrashArtifactRecord, CrashAnalysisRecord | None]]:
        with self.session_factory() as session:
            rows = session.execute(
                select(CrashArtifactRecord, CrashAnalysisRecord)
                .outerjoin(
                    CrashAnalysisRecord,
                    CrashAnalysisRecord.crash_id == CrashArtifactRecord.id,
                )
                .order_by(CrashArtifactRecord.created_at.desc())
            ).all()
            return [(artifact, analysis) for artifact, analysis in rows]

    def delete_crash(self, crash_id: str) -> None:
        core_path = None
        remove_core_file = False
        with self.session_factory() as session:
            record = session.get(CrashArtifactRecord, crash_id)
            if record is None:
                raise NotFoundError(f"크래시 로그를 찾을 수 없습니다: {crash_id}")
            if record.artifact_kind == "core_dump":
                core_path = self.crash_storage.path_for(record.sha256)
                sibling = session.scalar(
                    select(CrashArtifactRecord.id)
                    .where(
                        CrashArtifactRecord.artifact_kind == "core_dump",
                        CrashArtifactRecord.sha256 == record.sha256,
                        CrashArtifactRecord.id != crash_id,
                    )
                    .limit(1)
                )
                remove_core_file = sibling is None
            session.execute(
                delete(CrashAnalysisRecord).where(
                    CrashAnalysisRecord.crash_id == crash_id
                )
            )
            session.delete(record)
            session.add(
                AuditLogRecord(
                    action="crash.deleted",
                    resource_type="crash_artifact",
                    resource_id=crash_id,
                    detail={"filename": record.filename, "size": record.size},
                )
            )
            session.commit()
        if remove_core_file and core_path is not None:
            core_path.unlink(missing_ok=True)


def _safe_filename(filename: str, *, fallback: str) -> str:
    decoded_name = unquote(filename, errors="replace")
    name = decoded_name.replace("\\", "/").rsplit("/", 1)[-1].replace("\x00", "")
    name = "".join(char for char in name if char.isprintable())
    return name[:255] or fallback
