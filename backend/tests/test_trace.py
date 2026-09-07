"""실행 트레이스(Phase 6D 후속): ptrace 단일스텝으로 대상 실행 영역 주소 기록."""

from __future__ import annotations

import platform
import shutil
import subprocess

import pytest

from pwnable_lab.api.services import AnalysisService
from pwnable_lab.config import Settings
from pwnable_lab.elf.parser import parse_elf
from pwnable_lab.sandbox import SandboxLimits
from pwnable_lab.sandbox.trace import execution_trace

_SUPPORTED = platform.system() == "Linux" and platform.machine() in {"x86_64", "AMD64"}
_HAVE_GCC = shutil.which("gcc") is not None

_SRC = """
#include <stdio.h>
int add(int a, int b){ return a + b; }
int main(void){ setvbuf(stdout, 0, 2, 0); int r = add(2, 3); printf("%d", r); return 0; }
"""

_gated = pytest.mark.skipif(
    not (_SUPPORTED and _HAVE_GCC), reason="Linux/x86-64 + gcc 필요(실제 실행)"
)


def _compile(tmp_path) -> str:
    csrc = tmp_path / "t.c"
    csrc.write_text(_SRC)
    out = tmp_path / "t"
    subprocess.run(
        ["gcc", "-O0", "-no-pie", "-o", str(out), str(csrc)],
        check=True,
        capture_output=True,
    )
    return str(out)


def _main(path: str) -> int:
    return int(parse_elf(open(path, "rb").read()).symbol("main").addr)


@_gated
def test_trace_records_target_addresses(tmp_path):
    path = _compile(tmp_path)
    result = execution_trace(path, start=_main(path), max_steps=8000)
    assert result["attempted"] is True
    assert result["steps"] > 0
    assert result["unique_addresses"] > 0
    assert result["coverage_addresses"] == result["unique_addresses"]
    # 기록된 주소는 모두 대상 자신의 실행 영역(non-PIE → 0x40....) 안이어야 한다.
    lo, hi = 0x400000, 0x500000
    for hexaddr in result["trace"]:
        assert lo <= int(hexaddr, 16) < hi
    # 연속 중복이 접혔으므로 trace 는 단조로운 서로 다른 인접 주소열이다.
    assert (
        result["trace"][0] != result["trace"][1] if len(result["trace"]) > 1 else True
    )


@_gated
def test_trace_from_exec_stop_without_start(tmp_path):
    path = _compile(tmp_path)
    # start 없이 exec-stop 부터 짧게 트레이스(스텝 경로 커버).
    result = execution_trace(path, max_steps=200, limits=SandboxLimits())
    assert result["attempted"] is True
    assert result["steps"] > 0
    assert result["stopped"]["reason"] in {"timeout", "exited", "signal", "max-steps"}


@_gated
def test_trace_start_unset_is_reported(tmp_path):
    path = _compile(tmp_path)
    result = execution_trace(path, start=0x1, limits=SandboxLimits())
    assert result["attempted"] is False
    assert result["reason"] == "start-unset"


@_gated
def test_service_execution_trace_gated(tmp_path):
    path = _compile(tmp_path)
    service = AnalysisService(Settings(sandbox_execution_enabled=True))
    result = service.execution_trace(
        open(path, "rb").read(), start=_main(path), max_steps=8000
    )
    assert result["attempted"] is True
    assert result["steps"] > 0
