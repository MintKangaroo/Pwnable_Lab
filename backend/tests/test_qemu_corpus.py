"""QEMU 크로스아키텍처 골든 코퍼스: 여러 아키텍처 바이너리를 zig 로 빌드해 qemu 실행.

각 케이스는 zig(빌드)와 해당 ``qemu-<arch>-static``(실행)이 있을 때만 돈다. 없으면
그 케이스만 skip 한다(CI 안전). 엔디언에 따라 qemu 바이너리가 다른 mips/mipsel 도
`qemu_arch` 가 올바르게 구분하는지 함께 검증한다.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess

import pytest

from pwnable_lab.sandbox import SandboxLimits
from pwnable_lab.sandbox.qemu import locate_qemu, qemu_arch, run_under_qemu

_SUPPORTED = platform.system() == "Linux"
_ZIG = shutil.which("zig") or os.path.expanduser("~/.local/bin/zig")
_HAVE_ZIG = os.path.exists(_ZIG)

_SRC = (
    "#include <stdio.h>\n#include <unistd.h>\n"
    "int main(void){ char b[64]; setvbuf(stdout,0,2,0);"
    ' printf("ARCH_OK\\n"); int n=read(0,b,60);'
    ' if(n>0){ b[n>63?63:n]=0; printf("echo:%s", b); } return 5; }\n'
)

# (기대 arch, zig target, 기대 qemu 접미사)
_CASES = [
    ("aarch64", "aarch64-linux-musl", "aarch64"),
    ("arm", "arm-linux-musleabi", "arm"),
    ("mips", "mips-linux-musleabihf", "mips"),
    ("mipsel", "mipsel-linux-musleabi", "mipsel"),
]


def _build(tmp_path, target: str, name: str) -> str:
    csrc = tmp_path / f"{name}.c"
    csrc.write_text(_SRC)
    out = tmp_path / name
    subprocess.run(
        [_ZIG, "cc", "-target", target, "-static", "-O2", "-o", str(out), str(csrc)],
        check=True,
        capture_output=True,
    )
    return str(out)


@pytest.mark.parametrize("expected_arch,target,qemu_suffix", _CASES)
def test_cross_arch_runs_under_qemu(tmp_path, expected_arch, target, qemu_suffix):
    if not (_SUPPORTED and _HAVE_ZIG):
        pytest.skip("Linux + zig 필요")
    if locate_qemu(qemu_suffix) is None:
        pytest.skip(f"qemu-{qemu_suffix}-static 필요")

    path = _build(tmp_path, target, expected_arch)
    # 엔디언 인지 arch 판별이 정확한지(특히 mips vs mipsel).
    assert qemu_arch(open(path, "rb").read(64)) == expected_arch

    result = run_under_qemu(path, stdin_data=b"PING\n", limits=SandboxLimits())
    assert result["attempted"] is True, result
    assert result["arch"] == expected_arch
    assert result["exit_code"] == 5
    assert "ARCH_OK" in result["stdout"]
    assert "echo:PING" in result["stdout"]
