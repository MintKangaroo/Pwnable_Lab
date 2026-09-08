"""PE 동적 실행(wine): stdout/exit·stdin 왕복·Windows 예외(크래시) 검증."""

from __future__ import annotations

import platform
import shutil
import subprocess

import pytest

from pwnable_lab.api.services import AnalysisService
from pwnable_lab.config import Settings
from pwnable_lab.errors import SandboxError
from pwnable_lab.sandbox import SandboxLimits, pe_dynamic, run_pe
from pwnable_lab.sandbox.pe_dynamic import (
    _detect_crash,
    _has_wine32,
    _pe_bits,
    locate_wine,
)

_SUPPORTED = platform.system() == "Linux" and platform.machine() in {"x86_64", "AMD64"}
_HAVE_ZIG = shutil.which("zig") is not None
_HAVE_WINE = shutil.which("wine") is not None

_gated = pytest.mark.skipif(
    not (_SUPPORTED and _HAVE_ZIG and _HAVE_WINE),
    reason="Linux/x86-64 + zig + wine 필요(실제 PE 실행)",
)

_HELLO = '#include <stdio.h>\nint main(void){printf("PE-DYN-OK\\n");return 7;}\n'
_ECHO = (
    "#include <stdio.h>\n"
    "int main(void){char b[64];if(fgets(b,sizeof b,stdin))"
    'printf("GOT:%s",b);return 0;}\n'
)
_CRASH = "int main(void){volatile int*p=0;*p=1;return 0;}\n"


def _build(tmp_path, name: str, src: str) -> str:
    csrc = tmp_path / f"{name}.c"
    csrc.write_text(src)
    out = tmp_path / f"{name}.exe"
    subprocess.run(
        ["zig", "cc", "-target", "x86_64-windows", "-o", str(out), str(csrc)],
        check=True,
        capture_output=True,
    )
    return str(out)


@pytest.fixture(scope="module")
def wineprefix(tmp_path_factory):
    """모듈 공유 wineprefix — 부팅 비용을 한 번만 치른다."""

    return str(tmp_path_factory.mktemp("wpfx"))


@_gated
def test_run_pe_stdout_and_exit(tmp_path, wineprefix):
    exe = _build(tmp_path, "hello", _HELLO)
    result = run_pe(exe, wineprefix=wineprefix, limits=SandboxLimits())
    assert result["attempted"] is True
    assert result["bits"] == 64
    assert result["exit_code"] == 7
    assert result["crashed"] is False
    assert "PE-DYN-OK" in result["stdout"]


@_gated
def test_run_pe_stdin_roundtrip(tmp_path, wineprefix):
    exe = _build(tmp_path, "echo", _ECHO)
    result = run_pe(
        exe, stdin_data=b"pwn123\n", wineprefix=wineprefix, limits=SandboxLimits()
    )
    assert result["attempted"] is True
    assert "GOT:pwn123" in result["stdout"]


@_gated
def test_run_pe_crash_access_violation(tmp_path, wineprefix):
    exe = _build(tmp_path, "crash", _CRASH)
    result = run_pe(exe, wineprefix=wineprefix, limits=SandboxLimits())
    assert result["attempted"] is True
    assert result["crashed"] is True
    crash = result["crash"]
    assert crash["reason"] == "ACCESS_VIOLATION"
    assert crash["access"] == "write"
    assert crash["fault_address"] == "0x0"
    # winedbg 덤프는 stdout 에서 잘려 프로그램 출력만 남아야 한다(여기선 비어 있음).
    assert "Unhandled exception" not in result["stdout"]


def test_run_pe_rejects_non_pe(tmp_path):
    junk = tmp_path / "not.bin"
    junk.write_bytes(b"\x7fELF not a pe at all")
    result = run_pe(str(junk), limits=SandboxLimits())
    assert result["attempted"] is False
    assert result["reason"] == "not-pe"


def test_pe_bits_detects_magic():
    # 최소 PE64 헤더: MZ + e_lfanew=0x40 + 'PE\0\0' + magic 0x20b.
    head = bytearray(0x60)
    head[0:2] = b"MZ"
    head[0x3C:0x40] = (0x40).to_bytes(4, "little")
    head[0x40:0x44] = b"PE\x00\x00"
    head[0x58:0x5A] = (0x20B).to_bytes(2, "little")  # 0x40 + 24
    assert _pe_bits(bytes(head)) == 64
    head[0x58:0x5A] = (0x10B).to_bytes(2, "little")
    assert _pe_bits(bytes(head)) == 32
    assert _pe_bits(b"MZ" + b"\x00" * 4) is None  # 잘린 헤더


def test_detect_crash_from_stderr_fault_line():
    err = (
        "wine: Unhandled page fault on read access to 00000000DEADBEEF "
        "at address 0000000140001234 (thread 0024), starting debugger..."
    )
    crash = _detect_crash(0, err)
    assert crash == {
        "reason": "ACCESS_VIOLATION",
        "access": "read",
        "fault_address": "0xdeadbeef",
        "instruction_pointer": "0x140001234",
    }


def test_detect_crash_from_exit_code_and_none():
    assert _detect_crash(0xC0000094, "")["reason"] == "INTEGER_DIVIDE_BY_ZERO"
    assert _detect_crash(0, "clean exit, all good") is None
    # 예외 코드가 stderr 마커와 함께 온 경우(page fault 아님).
    marker = "unhandled exception c000001d in ..."
    assert _detect_crash(0, marker)["reason"] == "ILLEGAL_INSTRUCTION"


def test_service_pe_dynamic_run_gated_off():
    service = AnalysisService(Settings(sandbox_execution_enabled=False))
    with pytest.raises(SandboxError):
        service.pe_dynamic_run(b"MZ" + b"\x00" * 200)


@_gated
def test_service_pe_dynamic_run_end_to_end(tmp_path, wineprefix):
    exe = _build(tmp_path, "svc", _HELLO)
    service = AnalysisService(Settings(sandbox_execution_enabled=True))
    result = service.pe_dynamic_run(open(exe, "rb").read())
    assert result["attempted"] is True
    assert result["exit_code"] == 7
    assert "PE-DYN-OK" in result["stdout"]


def _pe_head(magic: int) -> bytes:
    head = bytearray(0x60)
    head[0:2] = b"MZ"
    head[0x3C:0x40] = (0x40).to_bytes(4, "little")
    head[0x40:0x44] = b"PE\x00\x00"
    head[0x58:0x5A] = magic.to_bytes(2, "little")
    return bytes(head)


def test_pe_bits_none_for_non_mz_and_unknown_magic():
    assert _pe_bits(b"not-an-mz-header" + b"\x00" * 64) is None
    assert _pe_bits(_pe_head(0x999)) is None  # 알 수 없는 optional magic


def test_run_pe_missing_file_raises():
    with pytest.raises(SandboxError):
        run_pe("/nonexistent/plab-no-such.exe", limits=SandboxLimits())


def test_run_pe_wine_unavailable(tmp_path, monkeypatch):
    exe = tmp_path / "x.exe"
    exe.write_bytes(_pe_head(0x20B))
    monkeypatch.setattr(pe_dynamic, "locate_wine", lambda: None)
    result = run_pe(str(exe), limits=SandboxLimits())
    assert result == {"attempted": False, "reason": "wine-unavailable"}


def test_run_pe_wine32_unavailable(tmp_path, monkeypatch):
    exe = tmp_path / "x32.exe"
    exe.write_bytes(_pe_head(0x10B))  # 32비트 PE
    monkeypatch.setattr(pe_dynamic, "locate_wine", lambda: "/usr/bin/wine")
    monkeypatch.setattr(pe_dynamic.shutil, "which", lambda name: None)
    monkeypatch.setattr(pe_dynamic, "_has_wine32", lambda wine: False)
    result = run_pe(str(exe), limits=SandboxLimits())
    assert result == {"attempted": False, "reason": "wine32-unavailable", "bits": 32}


def test_has_wine32_variants(tmp_path):
    # 존재하지 않는 실행 파일 → OSError → False.
    assert _has_wine32("/nonexistent/plab-wine") is False
    # "wine32 is missing" 경고를 내는 래퍼 → False.
    warn = tmp_path / "wine_warn.sh"
    warn.write_text('#!/bin/sh\necho "wine32 is missing" >&2\n')
    warn.chmod(0o755)
    assert _has_wine32(str(warn)) is False
    # 경고 없는 래퍼 → True.
    ok = tmp_path / "wine_ok.sh"
    ok.write_text('#!/bin/sh\necho "wine-9.0"\n')
    ok.chmod(0o755)
    assert _has_wine32(str(ok)) is True


def test_detect_crash_unhandled_fallback():
    # page fault 아니고 알려진 코드도 없지만 마커는 있음 → 일반 예외.
    crash = _detect_crash(0, "wine: starting debugger... something odd")
    assert crash == {"reason": "UNHANDLED_EXCEPTION"}


def test_locate_wine_returns_path_or_none():
    # 실제 환경에 의존하지 않는 스모크(경로 or None 둘 다 유효).
    assert locate_wine() is None or locate_wine().endswith("wine")
