"""Phase 6B 증분2: WebSocket 라이브 디버그 세션 API 계약.

게이트(기본 비활성)는 플랫폼 무관하게 돌고, 실제 세션 구동만 Linux/x86-64 + gcc 를
요구한다(없으면 해당 테스트만 skip).
"""

from __future__ import annotations

import platform
import shutil
import subprocess
from contextlib import contextmanager

import pytest

from pwnable_lab.elf.parser import parse_elf
from tests.fixtures import sample_elf

_SUPPORTED = platform.system() == "Linux" and platform.machine() in {"x86_64", "AMD64"}
_HAVE_GCC = shutil.which("gcc") is not None

_SRC = """
#include <stdio.h>
#include <unistd.h>
int add(int a, int b){ return a + b; }
int main(void){ setvbuf(stdout, 0, 2, 0); int r = add(3, 4); return r; }
"""


@contextmanager
def _make_client(tmp_path, monkeypatch, **env):
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


def _compile(tmp_path) -> bytes:
    csrc = tmp_path / "dbg.c"
    csrc.write_text(_SRC)
    out = tmp_path / "dbg"
    subprocess.run(
        ["gcc", "-fno-stack-protector", "-no-pie", "-O0", "-o", str(out), str(csrc)],
        check=True,
        capture_output=True,
    )
    return out.read_bytes()


def test_debug_ws_disabled_by_default_sends_error(tmp_path, monkeypatch):
    with _make_client(tmp_path, monkeypatch) as client:
        sha = _upload(client, sample_elf())
        with client.websocket_connect(f"/api/binaries/{sha}/debug/ws") as ws:
            frame = ws.receive_json()
            assert frame["event"] == "error"


def test_debug_ws_missing_binary_sends_error(tmp_path, monkeypatch):
    """게이트는 켜졌지만 존재하지 않는 바이너리면 오류 프레임 후 종료한다."""
    with _make_client(
        tmp_path, monkeypatch, PLAB_SANDBOX_EXECUTION_ENABLED="1"
    ) as client:
        with client.websocket_connect(f"/api/binaries/{'0' * 64}/debug/ws") as ws:
            frame = ws.receive_json()
            assert frame["event"] == "error"


@pytest.mark.skipif(
    not (_SUPPORTED and _HAVE_GCC),
    reason="Linux/x86-64 + gcc 필요(실제 실행/ptrace)",
)
def test_debug_ws_live_session(tmp_path, monkeypatch):
    binary = _compile(tmp_path)
    add = parse_elf(binary).symbol("add").addr
    with _make_client(
        tmp_path, monkeypatch, PLAB_SANDBOX_EXECUTION_ENABLED="1"
    ) as client:
        sha = _upload(client, binary, filename="dbg.elf")
        with client.websocket_connect(f"/api/binaries/{sha}/debug/ws") as ws:
            assert ws.receive_json()["event"] == "ready"
            ws.send_json({"op": "break", "addr": add})
            assert ws.receive_json()["ok"] is True
            ws.send_json({"op": "continue"})
            stop = ws.receive_json()
            assert stop["reason"] == "breakpoint"
            ws.send_json({"op": "registers"})
            regs = ws.receive_json()["registers"]
            assert regs["rdi"] == "0x3" and regs["rsi"] == "0x4"
            ws.send_json({"op": "continue"})
            assert ws.receive_json()["reason"] == "exited"
            ws.send_json({"op": "close"})


@pytest.mark.skipif(
    not (_SUPPORTED and _HAVE_GCC),
    reason="Linux/x86-64 + gcc 필요(실제 실행/ptrace)",
)
def test_debug_ws_client_disconnect_cleans_up(tmp_path, monkeypatch):
    """클라이언트가 close 없이 끊어도 서버가 세션을 정리한다(WebSocketDisconnect)."""
    binary = _compile(tmp_path)
    with _make_client(
        tmp_path, monkeypatch, PLAB_SANDBOX_EXECUTION_ENABLED="1"
    ) as client:
        sha = _upload(client, binary, filename="dbg.elf")
        with client.websocket_connect(f"/api/binaries/{sha}/debug/ws") as ws:
            assert ws.receive_json()["event"] == "ready"
            # with 블록을 나가며 close 프레임 없이 연결이 끊긴다.
