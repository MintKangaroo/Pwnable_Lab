"""SROP 자동 익스: sigreturn 으로 execve("/bin/sh") 셸 획득 증명."""

from __future__ import annotations

import platform
import shutil
import subprocess

import pytest

from pwnable_lab.analyzer.strategy import srop_plan
from pwnable_lab.api.services import AnalysisService
from pwnable_lab.config import Settings
from pwnable_lab.elf.parser import parse_elf
from pwnable_lab.payload.srop import build_sigreturn_frame
from pwnable_lab.sandbox import SandboxLimits
from pwnable_lab.sandbox.srop import auto_srop

_SUPPORTED = platform.system() == "Linux" and platform.machine() in {"x86_64", "AMD64"}
_HAVE_GCC = shutil.which("gcc") is not None

# pop rax·syscall 가젯 + /bin/sh + read 오버플로. pop rdi/rsi/rdx 는 없음(SROP 필요).
_SRC = """
#include <unistd.h>
__asm__(".global g_syscall_ret\\ng_syscall_ret:\\n syscall\\n ret\\n"
        ".global g_pop_rax\\ng_pop_rax:\\n pop %rax\\n ret\\n");
char binsh[] = "/bin/sh";
void vuln(void){ char b[64]; read(0, b, 0x400); }
int main(void){ vuln(); return 0; }
"""

_gated = pytest.mark.skipif(
    not (_SUPPORTED and _HAVE_GCC), reason="Linux/x86-64 + gcc 필요(실제 실행)"
)


def _compile(tmp_path) -> str:
    csrc = tmp_path / "srop.c"
    csrc.write_text(_SRC)
    out = tmp_path / "srop"
    subprocess.run(
        ["gcc", "-fno-stack-protector", "-no-pie", "-O0", "-o", str(out), str(csrc)],
        check=True,
        capture_output=True,
    )
    return str(out)


# --- sigreturn 프레임 단위(실행 불필요) -------------------------------------


def test_sigreturn_frame_layout():
    frame = build_sigreturn_frame(rip=0xDEAD, rax=59, rdi=0xB1, rsi=0, rdx=0)
    assert len(frame) == 0xF8
    # rip 오프셋 0xA8, rax 0x90, rdi 0x68, csgsfs 0xB8(기본 cs=0x33).
    assert frame[0xA8:0xB0] == (0xDEAD).to_bytes(8, "little")
    assert frame[0x90:0x98] == (59).to_bytes(8, "little")
    assert frame[0x68:0x70] == (0xB1).to_bytes(8, "little")
    assert frame[0xB8:0xC0] == (0x33).to_bytes(8, "little")


def test_sigreturn_frame_rejects_unknown_register():
    with pytest.raises(ValueError):
        build_sigreturn_frame(nope=1)


# --- 실 바이너리 셸 증명 ----------------------------------------------------


@_gated
def test_srop_plan_collects_materials(tmp_path):
    img = parse_elf(open(_compile(tmp_path), "rb").read())
    plan = srop_plan(img)
    assert plan is not None
    assert plan["pop_rax"] > 0 and plan["syscall"] > 0 and plan["binsh"] > 0


@_gated
def test_auto_srop_proves_shell(tmp_path):
    result = auto_srop(_compile(tmp_path), offset=72, limits=SandboxLimits())
    assert result["attempted"] is True
    assert result["technique"] == "srop"
    assert result["succeeded"] is True
    assert result["shell_proven"] is True
    assert result["shell_proof"]["shell_spawned"] is True


@_gated
def test_auto_srop_rejects_pie(tmp_path):
    csrc = tmp_path / "s.c"
    csrc.write_text(_SRC)
    out = tmp_path / "spie"
    subprocess.run(
        ["gcc", "-fno-stack-protector", "-pie", "-fPIE", "-o", str(out), str(csrc)],
        check=True,
        capture_output=True,
    )
    result = auto_srop(str(out), offset=72, limits=SandboxLimits())
    assert result["attempted"] is False
    assert result["reason"] == "pie-needs-base-leak"


@_gated
def test_auto_srop_no_plan(tmp_path):
    csrc = tmp_path / "b.c"
    csrc.write_text("int main(void){ return 0; }\n")
    out = tmp_path / "bare"
    subprocess.run(
        ["gcc", "-no-pie", "-o", str(out), str(csrc)], check=True, capture_output=True
    )
    result = auto_srop(str(out), offset=72, limits=SandboxLimits())
    assert result["attempted"] is False
    assert result["reason"] == "no-srop-plan"


@_gated
def test_auto_exploit_selects_srop(tmp_path):
    service = AnalysisService(
        Settings(sandbox_execution_enabled=True, sandbox_executor="inprocess")
    )
    result = service.auto_exploit(
        open(_compile(tmp_path), "rb").read(), pattern_length=400
    )
    v = result["verification"]
    assert v["technique"] == "srop"
    assert v["succeeded"] is True
    assert v["shell_proven"] is True
