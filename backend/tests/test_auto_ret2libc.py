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

    monkeypatch.setattr(
        "pwnable_lab.api.services.auto_ret2libc_in_container", fake
    )
    out = _service("container").auto_ret2libc(sample_elf(), offset=72)
    assert out == {"attempted": True, "technique": "ret2libc", "succeeded": True}
    assert calls["offset"] == 72


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
    # 계산한 libc 주소로 control 이 system(libc)으로 이전됐다.
    assert result["reached_libc"] is True
    assert result["succeeded"] is True
