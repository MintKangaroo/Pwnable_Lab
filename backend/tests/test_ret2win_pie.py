"""PIE 자동 ret2win: 로드 base 를 로컬 관측(ASLR-off)해 rebase 후 셸을 증명."""

from __future__ import annotations

import platform
import shutil
import subprocess

import pytest

from pwnable_lab.api.services import AnalysisService
from pwnable_lab.config import Settings
from pwnable_lab.sandbox import (
    auto_ret2system_pie_core,
    auto_ret2win_pie_core,
    resolve_pie_base,
)
from pwnable_lab.sandbox.runner import SandboxLimits

_SUPPORTED = platform.system() == "Linux" and platform.machine() in {"x86_64", "AMD64"}
_HAVE_GCC = shutil.which("gcc") is not None

_gated = pytest.mark.skipif(
    not (_SUPPORTED and _HAVE_GCC), reason="Linux/x86-64 + gcc 필요(실제 실행)"
)

_SRC = (
    "#include <stdio.h>\n#include <stdlib.h>\n#include <unistd.h>\n"
    'void win(void){ system("/bin/sh"); }\n'
    "void vuln(void){ char buf[64]; gets(buf); }\n"
    "int main(void){ vuln(); return 0; }\n"
)


def _compile_pie(tmp_path):
    csrc = tmp_path / "pie.c"
    csrc.write_text(_SRC)
    out = tmp_path / "pie"
    subprocess.run(
        ["gcc", "-fno-stack-protector", "-pie", "-fPIE", "-o", str(out), str(csrc)],
        check=True,
        capture_output=True,
    )
    return out


@_gated
def test_resolve_pie_base_is_deterministic(tmp_path):
    """ASLR-off 로 관측한 로드 base 는 재실행에도 동일(결정적)해야 한다."""
    out = str(_compile_pie(tmp_path))
    first = resolve_pie_base(out, limits=SandboxLimits())
    second = resolve_pie_base(out, limits=SandboxLimits())
    assert first.confirmed and first.base is not None
    assert second.confirmed
    # 관측 base 와 검증 base 가 일치해야 rebase 된 payload 가 성립한다.
    assert first.base == second.base


@_gated
def test_auto_ret2win_pie_core_proves_shell(tmp_path):
    out = str(_compile_pie(tmp_path))
    report = auto_ret2win_pie_core(out, offset=72, limits=SandboxLimits())
    assert report["attempted"] is True
    assert report["technique"] == "ret2win-pie"
    assert report["succeeded"] is True
    assert report["shell_proven"] is True
    assert report["reason"] == "shell-proven"
    # 런타임 타깃 = 관측 base + win 오프셋.
    assert report["base_hex"] is not None
    assert report["target_runtime_hex"] is not None
    assert report["shell_proof"]["shell_spawned"] is True


_FLAG_SRC = (
    "#include <stdio.h>\n#include <stdlib.h>\n#include <unistd.h>\n"
    'void win(void){ puts("FLAG{pie}"); exit(0); }\n'
    "void vuln(void){ char buf[64]; gets(buf); }\n"
    "int main(void){ vuln(); return 0; }\n"
)


@_gated
def test_auto_ret2win_pie_reports_control_transfer_when_no_shell(tmp_path):
    """win 이 셸을 안 띄우고 종료해도, 크래시 없이 제어 이전은 증명돼야 한다."""
    csrc = tmp_path / "flag.c"
    csrc.write_text(_FLAG_SRC)
    out = tmp_path / "flag"
    subprocess.run(
        ["gcc", "-fno-stack-protector", "-pie", "-fPIE", "-o", str(out), str(csrc)],
        check=True,
        capture_output=True,
    )
    report = auto_ret2win_pie_core(str(out), offset=72, limits=SandboxLimits())
    assert report["succeeded"] is True
    assert report["shell_proven"] is False
    assert report["reason"] == "control-transfer"
    assert report["verification"]["succeeded"] is True


@_gated
def test_auto_exploit_pie_is_shell_proven(tmp_path):
    out = _compile_pie(tmp_path)
    service = AnalysisService(
        Settings(sandbox_execution_enabled=True, sandbox_executor="inprocess")
    )
    result = service.auto_exploit(out.read_bytes(), pattern_length=200)
    v = result["verification"]
    assert v["attempted"] is True
    assert v["technique"] == "ret2win-pie"
    assert v["succeeded"] is True
    assert v["shell_proven"] is True


# PIE, win 함수 없음 — system + "/bin/sh" + pop rdi 가젯만 존재(ret2system 대상).
_SYS_SRC = (
    "#include <stdio.h>\n#include <stdlib.h>\n"
    '__asm__(".global g_pop_rdi\\ng_pop_rdi: pop %rdi\\n ret\\n");\n'
    'void never(void){ char *s="/bin/sh"; system(s); }\n'
    "void vuln(void){ char buf[64]; gets(buf); }\n"
    "int main(void){ vuln(); return 0; }\n"
)


def _compile_pie_sys(tmp_path):
    csrc = tmp_path / "psys.c"
    csrc.write_text(_SYS_SRC)
    out = tmp_path / "psys"
    subprocess.run(
        ["gcc", "-fno-stack-protector", "-pie", "-fPIE", "-o", str(out), str(csrc)],
        check=True,
        capture_output=True,
    )
    return out


@_gated
def test_auto_ret2system_pie_core_proves_shell(tmp_path):
    out = str(_compile_pie_sys(tmp_path))
    report = auto_ret2system_pie_core(out, offset=72, limits=SandboxLimits())
    assert report["attempted"] is True
    assert report["technique"] == "ret2system-pie"
    assert report["succeeded"] is True
    assert report["shell_proven"] is True
    assert report["reason"] == "shell-proven"
    assert report["base_hex"] is not None
    assert report["system_runtime_hex"] is not None
    assert report["shell_proof"]["shell_spawned"] is True


@_gated
def test_auto_exploit_pie_falls_back_to_ret2system(tmp_path):
    """win 함수가 없는 PIE 는 auto-exploit 이 ret2system-pie 로 셸을 증명해야 한다."""
    out = _compile_pie_sys(tmp_path)
    service = AnalysisService(
        Settings(sandbox_execution_enabled=True, sandbox_executor="inprocess")
    )
    result = service.auto_exploit(out.read_bytes(), pattern_length=200)
    v = result["verification"]
    assert v["attempted"] is True
    assert v["technique"] == "ret2system-pie"
    assert v["succeeded"] is True
    assert v["shell_proven"] is True
