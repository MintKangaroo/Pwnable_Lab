"""영속화 계층 테스트."""

from __future__ import annotations

import hashlib

import pytest

from pwnable_lab.database.repository import BinaryRepository
from pwnable_lab.database.session import make_engine, make_session_factory
from pwnable_lab.errors import NotFoundError


@pytest.fixture()
def repository(tmp_path):
    engine = make_engine("sqlite:///:memory:")
    return BinaryRepository(make_session_factory(engine), str(tmp_path / "files"))


def test_store_uses_content_hash_and_sanitizes_name(repository):
    record = repository.store(b"abc", r"..\folder/payload.elf", "EM_X86_64", 64)
    assert record.sha256 == hashlib.sha256(b"abc").hexdigest()
    assert record.filename == "payload.elf"
    assert repository.load_bytes(record.sha256) == b"abc"


def test_duplicate_store_returns_existing_record(repository):
    first = repository.store(b"same", "first.elf", "EM_X86_64", 64)
    second = repository.store(b"same", "second.elf", "EM_X86_64", 64)
    assert first.sha256 == second.sha256
    assert second.filename == "first.elf"
    assert len(repository.list()) == 1


def test_missing_and_malformed_hash_raise_not_found(repository):
    with pytest.raises(NotFoundError):
        repository.load_bytes("bad")
    with pytest.raises(NotFoundError):
        repository.get("0" * 64)


def test_submission_stats(repository):
    assert repository.stats("ret2win") == {"attempts": 0, "solved": 0}
    repository.record_submission("ret2win", False)
    repository.record_submission("ret2win", True)
    repository.record_submission("other", True)
    assert repository.stats("ret2win") == {"attempts": 2, "solved": 1}
