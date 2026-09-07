"""QEMU user-mode 실행(Phase 6D): 다른 아키텍처(aarch64) 바이너리 실행 관측."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess

import pytest

from pwnable_lab.api.services import AnalysisService
from pwnable_lab.config import Settings
from pwnable_lab.sandbox import SandboxLimits
from pwnable_lab.sandbox.qemu import locate_qemu, qemu_arch, run_under_qemu

_SUPPORTED = platform.system() == "Linux"
_ZIG = shutil.which("zig") or os.path.expanduser("~/.local/bin/zig")
_HAVE_ZIG = os.path.exists(_ZIG)
_HAVE_QEMU_AARCH64 = locate_qemu("aarch64") is not None

_SRC = (
    "#include <stdio.h>\n#include <unistd.h>\n"
    "int main(void){ char buf[64]; setvbuf(stdout,0,2,0);"
    ' printf("QEMU_ARM_OK\\n"); int n=read(0,buf,60);'
    ' if(n>0){ buf[n>63?63:n]=0; printf("echo:%s", buf); } return 7; }\n'
)

_gated = pytest.mark.skipif(
    not (_SUPPORTED and _HAVE_ZIG and _HAVE_QEMU_AARCH64),
    reason="Linux + zig + qemu-aarch64-static 필요(크로스아키텍처 실행)",
)


def _build_aarch64(tmp_path) -> str:
    csrc = tmp_path / "arm.c"
    csrc.write_text(_SRC)
    out = tmp_path / "arm"
    subprocess.run(
        [
            _ZIG,
            "cc",
            "-target",
            "aarch64-linux-musl",
            "-static",
            "-O2",
            "-o",
            str(out),
            str(csrc),
        ],
        check=True,
        capture_output=True,
    )
    return str(out)


def test_qemu_arch_from_elf_header():
    # aarch64 e_machine=0xB7, x86-64=0x3E; little-endian ELF64 헤더 최소 구성.
    def _hdr(machine: int) -> bytes:
        h = bytearray(20)
        h[0:4] = b"\x7fELF"
        h[4] = 2  # ELFCLASS64
        h[5] = 1  # little-endian
        h[18:20] = machine.to_bytes(2, "little")
        return bytes(h)

    assert qemu_arch(_hdr(0xB7)) == "aarch64"
    assert qemu_arch(_hdr(0x3E)) == "x86_64"
    assert qemu_arch(_hdr(0x28)) == "arm"
    assert qemu_arch(b"not elf") is None


def test_run_under_qemu_unknown_arch(tmp_path):
    p = tmp_path / "junk"
    p.write_bytes(b"\x7fELF" + b"\x00" * 60)  # e_machine=0 → 미지원
    result = run_under_qemu(str(p))
    assert result["attempted"] is False
    assert result["reason"] == "unknown-arch"


@_gated
def test_run_aarch64_binary_under_qemu(tmp_path):
    path = _build_aarch64(tmp_path)
    result = run_under_qemu(path, stdin_data=b"PING\n", limits=SandboxLimits())
    assert result["attempted"] is True
    assert result["arch"] == "aarch64"
    assert result["exit_code"] == 7
    assert "QEMU_ARM_OK" in result["stdout"]
    assert "echo:PING" in result["stdout"]


@_gated
def test_service_qemu_run_gated(tmp_path):
    path = _build_aarch64(tmp_path)
    service = AnalysisService(Settings(sandbox_execution_enabled=True))
    result = service.run_qemu(open(path, "rb").read(), stdin_data=b"HI\n")
    assert result["attempted"] is True
    assert result["exit_code"] == 7
    assert "echo:HI" in result["stdout"]


@_gated
def test_qemu_strace_captures_syscalls(tmp_path):
    path = _build_aarch64(tmp_path)
    result = run_under_qemu(
        path, stdin_data=b"PING\n", strace=True, limits=SandboxLimits()
    )
    assert result["attempted"] is True
    assert result["exit_code"] == 7
    syscalls = result["syscalls"]
    assert isinstance(syscalls, list) and syscalls
    joined = "\n".join(syscalls)
    # aarch64 binary 는 read/write 계열과 exit_group 을 호출한다.
    assert "read(" in joined
    assert "exit_group(" in joined
    # strace 모드에서는 syscall 트레이스가 stdout 에 섞이지 않는다.
    assert "QEMU_ARM_OK" in result["stdout"]
    assert "exit_group" not in result["stdout"]
