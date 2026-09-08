"""pytest 공용 픽스처."""

from __future__ import annotations

import os

import pytest

# 테스트는 항상 인메모리 DB + 임시 저장소를 쓴다.
os.environ.setdefault("PLAB_DATABASE_URL", "sqlite:///:memory:")

# 포터블 툴체인(zig/upx/qemu-*-static 등)은 ~/.local/bin 에 설치돼 있으나 비대화형
# 셸 PATH 에는 없을 수 있다. 툴 게이트 테스트가 결정적으로 돌도록 PATH 앞에 붙인다
# (존재하지 않는 환경에선 무해 — shutil.which 가 못 찾으면 기존처럼 skip).
_LOCAL_BIN = os.path.expanduser("~/.local/bin")
if os.path.isdir(_LOCAL_BIN) and _LOCAL_BIN not in os.environ.get("PATH", "").split(
    os.pathsep
):
    os.environ["PATH"] = _LOCAL_BIN + os.pathsep + os.environ.get("PATH", "")


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
