"""Phase 6A 동적 오프셋 확정 API 계약 테스트.

게이트/격리 마커/포맷 검증은 플랫폼 무관하게 돌고, 실제 오프셋 확정만
Linux/x86-64 + gcc 를 요구한다(없으면 해당 테스트만 skip).
"""

from __future__ import annotations

import platform
import shutil
import subprocess
from contextlib import contextmanager

import pytest

from tests.fixtures import sample_elf

_SUPPORTED = platform.system() == "Linux" and platform.machine() in {"x86_64", "AMD64"}
_HAVE_GCC = shutil.which("gcc") is not None

# buf[64] → 반환 주소 오프셋 72 (saved rbp 8 + 64).
_VULN_SRC = """
#include <stdio.h>
void vuln(void){ char buf[64]; gets(buf); }
int main(void){ vuln(); return 0; }
"""


@contextmanager
def _make_client(tmp_path, monkeypatch, **env):
    """지정한 PLAB_* 환경변수로 격리된 TestClient 를 구성한다."""
    from fastapi.testclient import TestClient

    from pwnable_lab.api import dependencies
    from pwnable_lab.api.app import create_app
    from pwnable_lab.config import get_settings

    monkeypatch.setenv("PLAB_STORAGE_DIR", str(tmp_path / "storage"))
    monkeypatch.setenv("PLAB_DATABASE_URL", "sqlite:///:memory:")
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    get_settings.cache_clear()
    dependencies._repo_for.cache_clear()
    try:
        with TestClient(create_app()) as client:
            yield client
    finally:
        get_settings.cache_clear()
        dependencies._repo_for.cache_clear()


def _upload(client, data, filename="sample.elf"):
    resp = client.post(
        "/api/binaries",
        files={"file": (filename, data, "application/octet-stream")},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["sha256"]


def _compile(tmp_path, src=_VULN_SRC):
    csrc = tmp_path / "vuln.c"
    csrc.write_text(src)
    out = tmp_path / "vuln"
    subprocess.run(
        ["gcc", "-fno-stack-protector", "-no-pie", "-o", str(out), str(csrc)],
        check=True,
        capture_output=True,
    )
    return out.read_bytes()


def test_disabled_by_default_returns_503(tmp_path, monkeypatch):
    with _make_client(tmp_path, monkeypatch) as client:
        sha = _upload(client, sample_elf())
        resp = client.post(f"/api/binaries/{sha}/confirm-offset")
        assert resp.status_code == 503
        assert resp.json()["error"] == "SandboxError"


def test_missing_binary_returns_404(tmp_path, monkeypatch):
    with _make_client(
        tmp_path, monkeypatch, PLAB_SANDBOX_EXECUTION_ENABLED="1"
    ) as client:
        resp = client.post("/api/binaries/" + "0" * 64 + "/confirm-offset")
        assert resp.status_code == 404


def test_missing_isolation_marker_returns_503(tmp_path, monkeypatch):
    with _make_client(
        tmp_path,
        monkeypatch,
        PLAB_SANDBOX_EXECUTION_ENABLED="1",
        PLAB_SANDBOX_ISOLATION_MARKER=str(tmp_path / "nope.marker"),
    ) as client:
        sha = _upload(client, sample_elf())
        resp = client.post(f"/api/binaries/{sha}/confirm-offset")
        assert resp.status_code == 503
        assert "격리 마커" in resp.json()["detail"]


def test_non_elf_is_rejected():
    """포맷 검증은 실행 게이트 통과 후 수행된다(비-ELF → AnalysisError)."""
    from pwnable_lab.api.services import AnalysisService
    from pwnable_lab.config import Settings
    from pwnable_lab.errors import AnalysisError

    service = AnalysisService(Settings(sandbox_execution_enabled=True))
    with pytest.raises(AnalysisError):
        service.confirm_offset(b"MZ\x90\x00 not an elf")


@pytest.mark.skipif(
    not (_SUPPORTED and _HAVE_GCC),
    reason="Linux/x86-64 + gcc 필요(실제 실행/ptrace)",
)
def test_confirms_offset_72_when_enabled(tmp_path, monkeypatch):
    binary = _compile(tmp_path)
    with _make_client(
        tmp_path, monkeypatch, PLAB_SANDBOX_EXECUTION_ENABLED="1"
    ) as client:
        sha = _upload(client, binary, filename="vuln.elf")
        resp = client.post(
            f"/api/binaries/{sha}/confirm-offset", params={"pattern_length": 400}
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["confirmed"] is True
        assert body["offset"] == 72
        assert body["verification"] == "verified"
        assert body["observation"]["crashed"] is True
