"""ORW(open→read→write) 자동 익스: seccomp 로 execve 막힌 환경에서 플래그 유출 증명."""

from __future__ import annotations

import platform
import shutil
import subprocess

import pytest

from pwnable_lab.analyzer.strategy import find_writable_buffer, orw_plan
from pwnable_lab.api.services import AnalysisService
from pwnable_lab.config import Settings
from pwnable_lab.elf.parser import parse_elf
from pwnable_lab.sandbox import SandboxLimits
from pwnable_lab.sandbox.orw import auto_orw, auto_orw_pie

_SUPPORTED = platform.system() == "Linux" and platform.machine() in {"x86_64", "AMD64"}
_HAVE_GCC = shutil.which("gcc") is not None
_MARKER = "PWNPILOT_FLAG{orw_works}"

# seccomp 로 execve 차단 + ORW 재료(클린 pop 가젯·syscall·.bss 버퍼·플래그 경로 문자열).
_SRC_TMPL = """
#include <stdio.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
__asm__(".global g_pops\\ng_pops:\\n pop %rdi\\n ret\\n pop %rsi\\n ret\\n"
        " pop %rdx\\n ret\\n pop %rax\\n ret\\n syscall\\n ret\\n");
char flagpath[] = "{FLAG}";
char scratch[512];
static void sb(void){
  static const struct sock_filter f[] = {
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS,4), BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,AUDIT_ARCH_X86_64,1,0),
    BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS), BPF_STMT(BPF_LD|BPF_W|BPF_ABS,0),
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,__NR_execve,1,0), BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
    BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
  };
  struct sock_fprog p={.len=sizeof(f)/sizeof(f[0]),.filter=(struct sock_filter*)f};
  prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0); prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&p);
}
void vuln(void){ char b[64]; read(0,b,0x300); }
int main(void){ setvbuf(stdout,0,2,0); sb(); vuln(); return 0; }
"""


def _headers_ok(tmp_path) -> bool:
    if not (_SUPPORTED and _HAVE_GCC):
        return False
    probe = tmp_path / "p.c"
    probe.write_text(
        "#include <linux/seccomp.h>\n#include <linux/filter.h>\nint main(void){return 0;}\n"
    )
    return (
        subprocess.run(
            ["gcc", "-o", str(tmp_path / "p"), str(probe)], capture_output=True
        ).returncode
        == 0
    )


def _build(tmp_path, *, pie: bool = False):
    flag = tmp_path / "flag.txt"
    flag.write_text(_MARKER + "\n")
    csrc = tmp_path / "orw.c"
    csrc.write_text(_SRC_TMPL.replace("{FLAG}", str(flag)))
    out = tmp_path / ("orw_pie" if pie else "orw")
    flags = ["-fno-stack-protector", "-O0"]
    flags += ["-pie", "-fPIE"] if pie else ["-no-pie"]
    subprocess.run(
        ["gcc", *flags, "-o", str(out), str(csrc)], check=True, capture_output=True
    )
    return str(out)


@pytest.mark.skipif(not (_SUPPORTED and _HAVE_GCC), reason="Linux/x86-64 + gcc 필요")
def test_orw_plan_and_writable_buffer(tmp_path):
    if not _headers_ok(tmp_path):
        pytest.skip("커널 seccomp 헤더 필요")
    img = parse_elf(open(_build(tmp_path), "rb").read())
    plan = orw_plan(img)
    assert plan is not None
    for key in ("pop_rdi", "pop_rsi", "pop_rdx", "pop_rax", "syscall", "buf"):
        assert plan[key] > 0
    assert find_writable_buffer(img, 256) is not None


@pytest.mark.skipif(not (_SUPPORTED and _HAVE_GCC), reason="Linux/x86-64 + gcc 필요")
def test_auto_orw_leaks_flag(tmp_path):
    if not _headers_ok(tmp_path):
        pytest.skip("커널 seccomp 헤더 필요")
    path = _build(tmp_path)
    result = auto_orw(
        path,
        offset=72,
        flag_path=str(tmp_path / "flag.txt"),
        expect_marker=_MARKER,
        limits=SandboxLimits(),
    )
    assert result["attempted"] is True
    assert result["technique"] == "orw"
    assert result["succeeded"] is True
    assert result["reason"] == "flag-leaked"
    assert _MARKER in result["leaked"]


@pytest.mark.skipif(not (_SUPPORTED and _HAVE_GCC), reason="Linux/x86-64 + gcc 필요")
def test_auto_orw_flag_path_not_in_binary(tmp_path):
    if not _headers_ok(tmp_path):
        pytest.skip("커널 seccomp 헤더 필요")
    result = auto_orw(
        _build(tmp_path),
        offset=72,
        flag_path="/nonexistent/path/xyz",
        limits=SandboxLimits(),
    )
    assert result["attempted"] is False
    assert result["reason"] == "flag-path-not-in-binary"


def test_auto_orw_rejects_pie(tmp_path):
    if not (_SUPPORTED and _HAVE_GCC):
        pytest.skip("Linux/x86-64 + gcc 필요")
    csrc = tmp_path / "pie.c"
    csrc.write_text(
        '#include <unistd.h>\nchar flagpath[]="/x";\nint main(void){ char b[64]; read(0,b,100); return 0; }\n'
    )
    out = tmp_path / "pie"
    subprocess.run(
        ["gcc", "-pie", "-fPIE", "-o", str(out), str(csrc)],
        check=True,
        capture_output=True,
    )
    result = auto_orw(str(out), offset=72, flag_path="/x", limits=SandboxLimits())
    assert result["attempted"] is False
    assert result["reason"] == "pie-needs-base-leak"


@pytest.mark.skipif(not (_SUPPORTED and _HAVE_GCC), reason="Linux/x86-64 + gcc 필요")
def test_auto_orw_pie_leaks_flag(tmp_path):
    if not _headers_ok(tmp_path):
        pytest.skip("커널 seccomp 헤더 필요")
    path = _build(tmp_path, pie=True)
    result = auto_orw_pie(
        path,
        offset=72,
        flag_path=str(tmp_path / "flag.txt"),
        expect_marker=_MARKER,
        limits=SandboxLimits(),
    )
    assert result["attempted"] is True
    assert result["technique"] == "orw-pie"
    assert result["succeeded"] is True
    assert result["aslr"] == "disabled-for-local-proof"
    assert result["base_hex"] is not None
    assert _MARKER in result["leaked"]


@pytest.mark.skipif(not (_SUPPORTED and _HAVE_GCC), reason="Linux/x86-64 + gcc 필요")
def test_auto_orw_pie_rejects_non_pie(tmp_path):
    if not _headers_ok(tmp_path):
        pytest.skip("커널 seccomp 헤더 필요")
    result = auto_orw_pie(
        _build(tmp_path),
        offset=72,
        flag_path=str(tmp_path / "flag.txt"),
        limits=SandboxLimits(),
    )
    assert result["attempted"] is False
    assert result["reason"] == "not-pie"


@pytest.mark.skipif(not (_SUPPORTED and _HAVE_GCC), reason="Linux/x86-64 + gcc 필요")
def test_service_auto_orw_gated(tmp_path):
    if not _headers_ok(tmp_path):
        pytest.skip("커널 seccomp 헤더 필요")
    path = _build(tmp_path)
    service = AnalysisService(Settings(sandbox_execution_enabled=True))
    result = service.auto_orw(
        open(path, "rb").read(),
        offset=72,
        flag_path=str(tmp_path / "flag.txt"),
        expect_marker=_MARKER,
    )
    assert result["succeeded"] is True
    assert _MARKER in result["leaked"]
