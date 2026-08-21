"""완전 자동 2단계 ret2libc: leak → libc base → system (libc ASLR 격파)."""

from __future__ import annotations

import platform
import shutil
import subprocess

import pytest

from pwnable_lab.api.services import AnalysisService
from pwnable_lab.config import Settings
from pwnable_lab.errors import SandboxError

_SUPPORTED = platform.system() == "Linux" and platform.machine() in {"x86_64", "AMD64"}
_HAVE_GCC = shutil.which("gcc") is not None

# 무버퍼 stdout(setvbuf) + puts/system//bin/sh 링크(never) + pop rdi 가젯.
_R2L_SRC = """
#include <stdio.h>
#include <stdlib.h>
__asm__(".global g_pop_rdi\\ng_pop_rdi: pop %rdi\\n ret\\n");
void never(void){ puts("x"); system("/bin/sh"); }
void vuln(void){ char buf[64]; gets(buf); }
int main(void){ setvbuf(stdout, 0, _IONBF, 0); vuln(); return 0; }
"""


def _service(executor="inprocess"):
    return AnalysisService(
        Settings(sandbox_execution_enabled=True, sandbox_executor=executor)
    )


def test_auto_ret2libc_disabled_raises():
    with pytest.raises(SandboxError):
        AnalysisService(Settings()).auto_ret2libc(b"\x7fELF", offset=72)


def test_auto_ret2libc_routes_to_container(monkeypatch):
    from tests.fixtures import sample_elf

    calls = {}

    def fake(data, *, offset, settings):
        calls.update(offset=offset)
        return {"attempted": True, "technique": "ret2libc", "succeeded": True}

    monkeypatch.setattr("pwnable_lab.api.services.auto_ret2libc_in_container", fake)
    out = _service("container").auto_ret2libc(sample_elf(), offset=72)
    assert out == {"attempted": True, "technique": "ret2libc", "succeeded": True}
    assert calls["offset"] == 72


@pytest.mark.skipif(not (_SUPPORTED and _HAVE_GCC), reason="Linux/x86-64 + gcc 필요")
def test_auto_ret2libc_pie_is_rejected(tmp_path):
    csrc = tmp_path / "pie.c"
    csrc.write_text(_R2L_SRC)
    out = tmp_path / "pie"
    subprocess.run(
        ["gcc", "-fno-stack-protector", "-pie", "-fPIE", "-o", str(out), str(csrc)],
        check=True,
        capture_output=True,
    )
    result = _service().auto_ret2libc(out.read_bytes(), offset=72)
    # PIE 는 절대주소 자동 체인 불가 → base leak 선행 필요를 명시.
    assert result["attempted"] is False
    assert result["reason"] == "pie-needs-base-leak"


@pytest.mark.skipif(
    not (_SUPPORTED and _HAVE_GCC), reason="Linux/x86-64 + gcc 필요(실제 실행)"
)
def test_auto_exploit_pie_verification_reports_pie(tmp_path):
    csrc = tmp_path / "pie2.c"
    csrc.write_text(_R2L_SRC)
    out = tmp_path / "pie2"
    subprocess.run(
        ["gcc", "-fno-stack-protector", "-pie", "-fPIE", "-o", str(out), str(csrc)],
        check=True,
        capture_output=True,
    )
    result = _service().auto_exploit(out.read_bytes(), pattern_length=400)
    # PIE 자동 익스: 로드 base 를 로컬 관측(ASLR-off)해 rebase. 이 바이너리엔 이름
    # 기반 win 함수(never 는 힌트 아님)가 없지만 system+"/bin/sh"+pop rdi 가 있어
    # ret2system-pie 로 폴백해 셸을 증명한다.
    v = result["verification"]
    assert v["attempted"] is True
    assert v["technique"] == "ret2system-pie"
    assert v["succeeded"] is True
    assert v["shell_proven"] is True


@pytest.mark.skipif(
    not (_SUPPORTED and _HAVE_GCC), reason="Linux/x86-64 + gcc 필요(실제 실행)"
)
def test_auto_ret2libc_end_to_end(tmp_path):
    csrc = tmp_path / "r2l.c"
    csrc.write_text(_R2L_SRC)
    out = tmp_path / "r2l"
    subprocess.run(
        ["gcc", "-fno-stack-protector", "-no-pie", "-o", str(out), str(csrc)],
        check=True,
        capture_output=True,
    )
    data = out.read_bytes()

    result = _service().auto_ret2libc(data, offset=72)
    assert result["attempted"] is True
    assert result["technique"] == "ret2libc"
    # leak 으로 base 를 계산했고, 페이지 정렬이면 계산이 정확하다는 강한 증거.
    assert result["libc_base"] is not None
    assert result["libc_base_page_aligned"] is True
    assert result["leaked_puts"] > 0x100000000000
    # 계산한 libc 주소로 system("/bin/sh") 를 띄우고, PTY 로 셸이 명령을 실행함을 증명.
    assert result["shell_proven"] is True
    assert result["succeeded"] is True
    assert result["reason"] == "shell-proven"
    assert result["shell_proof"]["shell_spawned"] is True
