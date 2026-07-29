"""pytest 공용 픽스처."""

from __future__ import annotations

import os

import pytest

# 테스트는 항상 인메모리 DB + 임시 저장소를 쓴다.
os.environ.setdefault("PLAB_DATABASE_URL", "sqlite:///:memory:")


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """격리된 TestClient (인메모리 DB, 임시 스토리지)."""
    from pwnable_lab.api import dependencies
    from pwnable_lab.config import get_settings

    monkeypatch.setenv("PLAB_STORAGE_DIR", str(tmp_path / "storage"))
    monkeypatch.setenv("PLAB_DATABASE_URL", "sqlite:///:memory:")
    get_settings.cache_clear()
    dependencies._repo_for.cache_clear()

    from fastapi.testclient import TestClient

    from pwnable_lab.api.app import create_app

    with TestClient(create_app()) as c:
        yield c

    get_settings.cache_clear()
    dependencies._repo_for.cache_clear()
