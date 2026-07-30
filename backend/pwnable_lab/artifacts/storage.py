"""청크 기반 업로드와 콘텐츠 주소 방식 원자적 저장.

업로드 바이트는 호스트에서 실행되지 않는다. 임시 파일은 최종 저장소와 같은
파일시스템에 만들고, 완전히 기록되고 검증된 뒤에만 SHA-256 이름으로 채택한다.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from pwnable_lab.errors import PayloadTooLargeError


class AsyncByteReader(Protocol):
    async def read(self, size: int = -1) -> bytes:
        """최대 ``size`` 바이트를 읽는다."""


@dataclass(frozen=True)
class StagedArtifact:
    path: Path
    sha256: str
    size: int


@dataclass
class ArtifactStorage:
    root: Path

    @classmethod
    def from_path(cls, root: str | os.PathLike[str]) -> ArtifactStorage:
        return cls(Path(root))

    def __post_init__(self) -> None:
        self.root.mkdir(mode=0o750, parents=True, exist_ok=True)

    async def stage(
        self,
        reader: AsyncByteReader,
        *,
        max_bytes: int,
        chunk_bytes: int,
    ) -> StagedArtifact:
        """업로드를 제한된 청크로 읽어 임시 파일에 기록하고 해시한다."""
        file_descriptor, raw_path = tempfile.mkstemp(prefix=".upload-", dir=self.root)
        path = Path(raw_path)
        digest = hashlib.sha256()
        total = 0
        try:
            with os.fdopen(file_descriptor, "wb") as handle:
                while True:
                    chunk = await reader.read(chunk_bytes)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise PayloadTooLargeError(
                            f"업로드 크기가 한계({max_bytes} bytes)를 초과했습니다."
                        )
                    digest.update(chunk)
                    handle.write(chunk)
                handle.flush()
                os.fsync(handle.fileno())
            return StagedArtifact(path=path, sha256=digest.hexdigest(), size=total)
        except BaseException:
            path.unlink(missing_ok=True)
            raise

    def stage_bytes(self, data: bytes) -> StagedArtifact:
        """테스트/내부 생성 artifact를 업로드와 같은 원자적 경로로 준비한다."""
        file_descriptor, raw_path = tempfile.mkstemp(prefix=".artifact-", dir=self.root)
        path = Path(raw_path)
        try:
            with os.fdopen(file_descriptor, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            return StagedArtifact(
                path=path,
                sha256=hashlib.sha256(data).hexdigest(),
                size=len(data),
            )
        except BaseException:
            path.unlink(missing_ok=True)
            raise

    def commit(self, staged: StagedArtifact) -> Path:
        """검증된 임시 파일을 기존 객체를 덮어쓰지 않고 원자적으로 채택한다."""
        destination = self.path_for(staged.sha256)
        try:
            os.link(staged.path, destination)
        except FileExistsError:
            pass
        finally:
            staged.path.unlink(missing_ok=True)
        return destination

    def discard(self, staged: StagedArtifact) -> None:
        staged.path.unlink(missing_ok=True)

    def path_for(self, sha256: str) -> Path:
        if len(sha256) != 64 or any(c not in "0123456789abcdef" for c in sha256):
            raise ValueError("유효한 SHA-256 식별자가 아닙니다.")
        return self.root / sha256
