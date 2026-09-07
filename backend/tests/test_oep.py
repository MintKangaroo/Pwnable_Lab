"""OEP 후보 탐지(Phase 6D): 쓰기 가능·익명 실행으로의 tail jump 를 ptrace 로 관측."""

from __future__ import annotations

import platform
import shutil
import subprocess

import pytest

from pwnable_lab.api.services import AnalysisService
from pwnable_lab.config import Settings
from pwnable_lab.elf.parser import parse_elf
from pwnable_lab.sandbox import SandboxLimits
from pwnable_lab.sandbox.oep import find_oep_candidate

_SUPPORTED = platform.system() == "Linux" and platform.machine() in {"x86_64", "AMD64"}
_HAVE_GCC = shutil.which("gcc") is not None

# RWX 익명 페이지에 코드를 쓰고 점프 → 언패커 tail jump 를 흉내낸다.
_UNPACK_SRC = """
#include <sys/mman.h>
#include <string.h>
#include <stdio.h>
void gate(void){ }
int main(void){
  setvbuf(stdout, 0, 2, 0);
  unsigned char *p = mmap(0, 4096, PROT_READ|PROT_WRITE|PROT_EXEC,
                          MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  unsigned char code[] = {0x90, 0x90, 0x90, 0xc3};  /* nop nop nop ret */
  memcpy(p, code, sizeof code);
  gate();
  ((void(*)(void))p)();
  return 0;
}
"""

# 정상(W^X 준수) 바이너리: 쓰기 가능 메모리를 실행하지 않는다.
_NORMAL_SRC = """
#include <stdio.h>
void gate(void){ }
int main(void){ setvbuf(stdout, 0, 2, 0); gate(); puts("done"); return 0; }
"""

_gated = pytest.mark.skipif(
    not (_SUPPORTED and _HAVE_GCC), reason="Linux/x86-64 + gcc 필요(실제 실행)"
)


def _compile(tmp_path, src: str, name: str) -> str:
    csrc = tmp_path / f"{name}.c"
    csrc.write_text(src)
    out = tmp_path / name
    subprocess.run(
        ["gcc", "-no-pie", "-O0", "-o", str(out), str(csrc)],
        check=True,
        capture_output=True,
    )
    return str(out)


def _gate(path: str) -> int:
    return int(parse_elf(open(path, "rb").read()).symbol("gate").addr)


@_gated
def test_detects_tail_jump_to_writable_exec(tmp_path):
    path = _compile(tmp_path, _UNPACK_SRC, "unpack")
    result = find_oep_candidate(path, start=_gate(path), limits=SandboxLimits())
    assert result["attempted"] is True
    assert result["oep_candidate"] is not None
    assert result["reason"] == "tail-jump-to-writable-exec"
    # 후보 영역은 쓰기 가능하거나 익명이어야 한다.
    perms = result["region"]["perms"]
    assert "w" in perms or result["region"]["path"] == ""


@_gated
def test_normal_binary_has_no_oep_candidate(tmp_path):
    path = _compile(tmp_path, _NORMAL_SRC, "normal")
    result = find_oep_candidate(
        path, start=_gate(path), max_steps=20_000, limits=SandboxLimits()
    )
    assert result["attempted"] is True
    assert result["oep_candidate"] is None
    assert result["reason"] in {"exited", "max-steps"}


@_gated
def test_start_not_hit_is_reported(tmp_path):
    path = _compile(tmp_path, _NORMAL_SRC, "normal2")
    # 매핑 안 된 주소에서 시작 → start-unset.
    result = find_oep_candidate(path, start=0x1, limits=SandboxLimits())
    assert result["attempted"] is False
    assert result["reason"] == "start-unset"


@_gated
def test_service_oep_gated(tmp_path):
    path = _compile(tmp_path, _UNPACK_SRC, "unpack2")
    service = AnalysisService(Settings(sandbox_execution_enabled=True))
    result = service.oep_candidate(open(path, "rb").read(), start=_gate(path))
    assert result["attempted"] is True
    assert result["oep_candidate"] is not None
