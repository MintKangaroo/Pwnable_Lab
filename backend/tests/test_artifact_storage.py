"""청크 업로드와 원자적 콘텐츠 저장 테스트."""

from __future__ import annotations

import asyncio

import pytest

from pwnable_lab.artifacts.storage import ArtifactStorage
from pwnable_lab.errors import PayloadTooLargeError


class ChunkReader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = 0
        self.read_sizes: list[int] = []

    async def read(self, size: int = -1) -> bytes:
        self.read_sizes.append(size)
        if self.offset >= len(self.data):
            return b""
        end = len(self.data) if size < 0 else self.offset + size
        chunk = self.data[self.offset : end]
        self.offset += len(chunk)
        return chunk


def test_stage_reads_bounded_chunks_and_commit_is_deduplicated(tmp_path):
    storage = ArtifactStorage(tmp_path / "objects")
    reader = ChunkReader(b"\x7fELF" + b"A" * 100)
    staged = asyncio.run(storage.stage(reader, max_bytes=1024, chunk_bytes=16))
    assert staged.size == 104
    assert all(size == 16 for size in reader.read_sizes)

    destination = storage.commit(staged)
    assert destination.read_bytes() == b"\x7fELF" + b"A" * 100
    duplicate = storage.stage_bytes(b"\x7fELF" + b"A" * 100)
    assert storage.commit(duplicate) == destination
    assert destination.read_bytes() == b"\x7fELF" + b"A" * 100


def test_oversized_stage_cleans_temporary_file(tmp_path):
    storage = ArtifactStorage(tmp_path / "objects")
    reader = ChunkReader(b"A" * 65)
    with pytest.raises(PayloadTooLargeError):
        asyncio.run(storage.stage(reader, max_bytes=64, chunk_bytes=16))
    assert list(storage.root.glob(".upload-*")) == []
