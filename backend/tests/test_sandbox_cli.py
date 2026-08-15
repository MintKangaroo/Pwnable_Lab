"""일회용 샌드박스 CLI 워커 테스트.

게이트/사용법 오류는 플랫폼 무관, 실제 오프셋 확정만 Linux/x86-64 + gcc 요구.
"""

from __future__ import annotations

import json
import platform
import shutil
import subprocess

import pytest

from pwnable_lab.config import get_settings
from pwnable_lab.sandbox import cli

_SUPPORTED = platform.system() == "Linux" and platform.machine() in {"x86_64", "AMD64"}
_HAVE_GCC = shutil.which("gcc") is not None

_VULN_SRC = """
#include <stdio.h>
void vuln(void){ char buf[64]; gets(buf); }
int main(void){ vuln(); return 0; }
"""


@pytest.fixture()
def _clean_settings(monkeypatch):
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _enable(monkeypatch, tmp_path=None):
    monkeypatch.setenv("PLAB_SANDBOX_EXECUTION_ENABLED", "1")
    if tmp_path is not None:
        marker = tmp_path / "marker"
        marker.write_text("x")
        monkeypatch.setenv("PLAB_SANDBOX_ISOLATION_MARKER", str(marker))
    get_settings.cache_clear()


def _compile(tmp_path):
    csrc = tmp_path / "vuln.c"
    csrc.write_text(_VULN_SRC)
    out = tmp_path / "vuln"
    subprocess.run(
        ["gcc", "-fno-stack-protector", "-no-pie", "-o", str(out), str(csrc)],
        check=True,
        capture_output=True,
    )
    return out


def test_gate_disabled_returns_2(monkeypatch, capsys, _clean_settings):
    monkeypatch.delenv("PLAB_SANDBOX_EXECUTION_ENABLED", raising=False)
    get_settings.cache_clear()
    code = cli.main(["/bin/true"])
    assert code == 2
    assert "게이트 거부" in capsys.readouterr().err


def test_missing_marker_returns_2(monkeypatch, capsys, tmp_path, _clean_settings):
    monkeypatch.setenv("PLAB_SANDBOX_EXECUTION_ENABLED", "1")
    monkeypatch.setenv("PLAB_SANDBOX_ISOLATION_MARKER", str(tmp_path / "nope"))
    get_settings.cache_clear()
    assert cli.main(["/bin/true"]) == 2


def test_missing_file_returns_3(monkeypatch, capsys, tmp_path, _clean_settings):
    _enable(monkeypatch)
    code = cli.main([str(tmp_path / "does-not-exist")])
    assert code == 3


@pytest.mark.skipif(
    not (_SUPPORTED and _HAVE_GCC),
    reason="Linux/x86-64 + gcc 필요(실제 실행/ptrace)",
)
def test_confirms_offset_via_path(monkeypatch, capsys, tmp_path, _clean_settings):
    binary = _compile(tmp_path)
    _enable(monkeypatch, tmp_path)
    code = cli.main([str(binary), "--pattern-length", "400"])
    assert code == 0
    out = json.loads(capsys.readouterr().out)
    assert out["confirmed"] is True
    assert out["offset"] == 72
    assert out["verification"] == "verified"


@pytest.mark.skipif(
    not (_SUPPORTED and _HAVE_GCC),
    reason="Linux/x86-64 + gcc 필요(실제 실행/ptrace)",
)
def test_confirms_offset_via_stdin(monkeypatch, capsys, tmp_path, _clean_settings):
    binary = _compile(tmp_path)
    _enable(monkeypatch, tmp_path)

    class _Buf:
        def __init__(self, data):
            self.buffer = self

        def read(self):
            return binary.read_bytes()

    monkeypatch.setattr("sys.stdin", _Buf(None))
    code = cli.main(["--stdin", "--pattern-length", "400"])
    assert code == 0
    out = json.loads(capsys.readouterr().out)
    assert out["confirmed"] is True
    assert out["offset"] == 72
