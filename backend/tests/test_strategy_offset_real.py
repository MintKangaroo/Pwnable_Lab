"""실 gcc 바이너리로 오프셋 추론(F-CRIT-1 회귀)을 검증한다.

합성 ``ElfBuilder`` 픽스처는 gcc 의 간접 버퍼 로드 관용구
(``lea rax, [rbp - N]; mov rdi, rax``)를 재현하지 못하므로, 그 경로에서
``_infer_offset`` 이 오프셋을 산출하지 못하던 회귀를 잡으려면 실제 컴파일
바이너리가 필요하다. gcc/x86-64 가 없으면 skip.
"""

from __future__ import annotations

import platform
import shutil
import subprocess

import pytest

from pwnable_lab.analyzer.strategy import analyze_strategy
from pwnable_lab.elf.parser import parse_elf

_SUPPORTED = platform.system() == "Linux" and platform.machine() in {
    "x86_64",
    "AMD64",
}
_HAVE_GCC = shutil.which("gcc") is not None

pytestmark = pytest.mark.skipif(
    not (_SUPPORTED and _HAVE_GCC),
    reason="Linux/x86-64 + gcc 필요(실 컴파일러 관용구 재현)",
)

# buf[64] → 반환 주소 오프셋 = 0x40 + 8(saved rbp) = 72.
_VULN_SRC = """
#include <stdio.h>
#include <stdlib.h>
void win(void){ system("/bin/sh"); }
void vuln(void){ char buf[64]; gets(buf); }
int main(void){ vuln(); return 0; }
"""


def _strategy_for(tmp_path, *flags):
    csrc = tmp_path / "vuln.c"
    csrc.write_text(_VULN_SRC)
    out = tmp_path / "vuln"
    subprocess.run(
        ["gcc", "-fno-stack-protector", "-no-pie", *flags, "-o", str(out), str(csrc)],
        check=True,
        capture_output=True,
    )
    return analyze_strategy(parse_elf(out.read_bytes()))


def test_infers_ret2win_offset_from_indirect_buffer_load(tmp_path):
    """gcc -O0 의 `lea rax,[rbp-0x40]; mov rdi,rax` 에서 오프셋 72 를 산출한다."""
    report = _strategy_for(tmp_path)
    ret2win = next(p for p in report["paths"] if p["id"] == "ret2win")
    skeleton = ret2win["pwntools"]
    # 회귀 핵심: placeholder(`offset = 0`)가 아니라 확정 오프셋 72 여야 한다.
    assert "offset = 72" in skeleton
    assert "offset = 0" not in skeleton
    assert "[rbp - 0x40]" in skeleton
