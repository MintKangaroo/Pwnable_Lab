"""libc 주소 leak(ASLR 우회 1단계): puts(puts@got) → exit 체인."""

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

# puts/exit 를 PLT 에 링크(never 는 실행 안 함 → 시작 출력 없음). pop rdi 가젯은
# 인라인 asm 으로 확실히 심는다. vuln 의 buf[64] → 반환 오프셋 72.
_LEAK_SRC = """
#include <stdio.h>
#include <stdlib.h>
__asm__(".global g_pop_rdi\\ng_pop_rdi: pop %rdi\\n ret\\n");
void never(void){ puts("x"); }
void vuln(void){ char buf[64]; gets(buf); }
int main(void){ vuln(); exit(0); }
"""


def _service():
    return AnalysisService(
        Settings(sandbox_execution_enabled=True, sandbox_executor="inprocess")
    )


def test_leak_disabled_raises():
    with pytest.raises(SandboxError):
        AnalysisService(Settings()).verify_leak(b"\x7fELF", offset=72)


@pytest.mark.skipif(
    not (_SUPPORTED and _HAVE_GCC), reason="Linux/x86-64 + gcc 필요(실제 실행)"
)
def test_leak_recovers_libc_pointer(tmp_path):
    csrc = tmp_path / "leak.c"
    csrc.write_text(_LEAK_SRC)
    out = tmp_path / "leak"
    subprocess.run(
        ["gcc", "-fno-stack-protector", "-no-pie", "-o", str(out), str(csrc)],
        check=True,
        capture_output=True,
    )
    data = out.read_bytes()

    from pwnable_lab.analyzer.strategy import leak_plan
    from pwnable_lab.elf.parser import parse_elf

    assert leak_plan(parse_elf(data)) is not None, "leak 구성요소를 못 찾음"

    result = _service().verify_leak(data, offset=72)
    assert result["attempted"] is True
    assert result["succeeded"] is True
    # 유출값은 상위 비트가 살아 있는 실제 libc 포인터(6바이트 주소)여야 한다.
    assert result["leaked_addr"] > 0x100000000000
    assert result["leaked_hex"].startswith("0x7")
