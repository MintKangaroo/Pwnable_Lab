"""PIE execve syscall ROP 자동 익스: 로드 base 관측·rebase 후 셸 획득 증명."""

from __future__ import annotations

import platform
import shutil
import subprocess

import pytest

from pwnable_lab.analyzer.strategy import execve_plan, is_pie, ret2system_plan
from pwnable_lab.api.services import AnalysisService
from pwnable_lab.config import Settings
from pwnable_lab.elf.parser import parse_elf
from pwnable_lab.sandbox import auto_execve_pie_core
from pwnable_lab.sandbox.runner import SandboxLimits

_SUPPORTED = platform.system() == "Linux" and platform.machine() in {"x86_64", "AMD64"}
_HAVE_GCC = shutil.which("gcc") is not None

# system 미참조(ret2system 불가) PIE. 각 인자 레지스터 pop 가젯 + syscall 가젯 +
# 자체 /bin/sh 문자열을 심어 execve syscall ROP 만 성립하게 한다.
_EXECVE_PIE_SRC = """
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


def _compile_pie(tmp_path):
    csrc = tmp_path / "execve_pie.c"
    csrc.write_text(_EXECVE_PIE_SRC)
    out = tmp_path / "execve_pie"
    subprocess.run(
        ["gcc", "-fno-stack-protector", "-pie", "-fPIE", "-o", str(out), str(csrc)],
        check=True,
        capture_output=True,
    )
    return out


@_gated
def test_execve_pie_binary_is_pie_without_system(tmp_path):
    img = parse_elf(_compile_pie(tmp_path).read_bytes())
    assert is_pie(img) is True
    assert execve_plan(img) is not None
    # system 을 링크하지 않으므로 ret2system 은 불가 → execve 로만 성립.
    assert ret2system_plan(img) is None


@_gated
def test_auto_execve_pie_core_proves_shell(tmp_path):
    out = str(_compile_pie(tmp_path))
    report = auto_execve_pie_core(out, offset=72, limits=SandboxLimits())
    assert report["attempted"] is True
    assert report["technique"] == "execve-pie"
    assert report["succeeded"] is True
    assert report["shell_proven"] is True
    assert report["reason"] == "shell-proven"
    # 런타임 주소 = 관측 base + 정적 오프셋.
    assert report["base_hex"] is not None
    assert report["binsh_runtime_hex"] is not None
    assert report["syscall_runtime_hex"] is not None
    assert report["aslr"] == "disabled-for-local-proof"
    assert report["shell_proof"]["shell_spawned"] is True


@_gated
def test_auto_exploit_selects_execve_pie(tmp_path):
    out = _compile_pie(tmp_path)
    service = AnalysisService(
        Settings(sandbox_execution_enabled=True, sandbox_executor="inprocess")
    )
    result = service.auto_exploit(out.read_bytes(), pattern_length=400)
    v = result["verification"]
    assert v["technique"] == "execve-pie"
    assert v["succeeded"] is True
    assert v["shell_proven"] is True
    assert v["reason"] == "shell-proven"
    assert v["aslr"] == "disabled-for-local-proof"
