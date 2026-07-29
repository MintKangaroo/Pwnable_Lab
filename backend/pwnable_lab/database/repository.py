"""저장소(repository) — 바이너리 바이트는 디스크에, 메타데이터는 DB에.

파일은 항상 콘텐츠 해시(sha256)로 명명한다. 사용자 입력이 파일 경로에 닿지 않으므로
경로 조작이 원천 차단된다.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from pwnable_lab.database.models import BinaryRecord, SubmissionRecord
from pwnable_lab.errors import NotFoundError


@dataclass
class BinaryRepository:
    session_factory: sessionmaker
    storage_dir: str

    def __post_init__(self) -> None:
        os.makedirs(self.storage_dir, exist_ok=True)

    # --- 바이너리 ---
    def _path(self, sha256: str) -> str:
        # sha256 은 검증된 16진수 문자열이어야 한다.
        if len(sha256) != 64 or any(c not in "0123456789abcdef" for c in sha256):
            raise NotFoundError("잘못된 바이너리 식별자입니다.")
        return os.path.join(self.storage_dir, sha256)

    def store(self, data: bytes, filename: str, machine: str, bits: int) -> BinaryRecord:
        sha256 = hashlib.sha256(data).hexdigest()
        path = self._path(sha256)
        try:
            # 같은 콘텐츠가 동시에 도착해도 기존 파일을 덮어쓰지 않는다.
            with open(path, "xb") as fh:
                fh.write(data)
        except FileExistsError:
            pass
        safe_name = filename.replace("\\", "/").rsplit("/", 1)[-1].replace("\x00", "")
        safe_name = safe_name[:255] or "binary"
        with self.session_factory() as session:
            existing = session.get(BinaryRecord, sha256)
            if existing:
                return existing
            record = BinaryRecord(
                sha256=sha256, filename=safe_name, size=len(data),
                machine=machine, bits=bits,
            )
            session.add(record)
            session.commit()
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
            return list(session.scalars(
                select(BinaryRecord).order_by(BinaryRecord.created_at.desc())
            ))

    # --- 제출 기록 ---
    def record_submission(self, slug: str, correct: bool) -> None:
        with self.session_factory() as session:
            session.add(SubmissionRecord(slug=slug, correct=1 if correct else 0))
            session.commit()

    def stats(self, slug: str) -> dict:
        with self.session_factory() as session:
            rows = list(session.scalars(
                select(SubmissionRecord).where(SubmissionRecord.slug == slug)
            ))
        total = len(rows)
        solved = sum(r.correct for r in rows)
        return {"attempts": total, "solved": solved}
