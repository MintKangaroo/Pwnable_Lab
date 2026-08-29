"""Phase 6A 오프셋 확정 러너 테스트.

실제 프로세스를 fork/ptrace 하고 gcc 로 취약 바이너리를 컴파일하므로,
Linux/x86-64 + gcc 가 없으면 skip 한다(합성 픽스처로는 재현 불가한 경로다).
"""

from __future__ import annotations

import platform
import shutil
import subprocess

import pytest

from pwnable_lab.errors import SandboxError
from pwnable_lab.sandbox import (
    SandboxLimits,
    confirm_return_offset,
    run_with_input,
)

_SUPPORTED = platform.system() == "Linux" and platform.machine() in {
    "x86_64",
    "AMD64",
}
_HAVE_GCC = shutil.which("gcc") is not None

pytestmark = pytest.mark.skipif(
    not (_SUPPORTED and _HAVE_GCC),
    reason="Linux/x86-64 + gcc 필요(실제 실행/ptrace 테스트)",
)

# buf[64] → 반환 주소 오프셋 = 0x40 + 8(saved rbp) = 72.
_VULN_SRC = """
#include <stdio.h>
void vuln(void){ char buf[64]; gets(buf); }
int main(void){ vuln(); return 0; }
"""
_SAFE_SRC = "int main(void){ return 0; }\n"
_HANG_SRC = "int main(void){ for(;;){} return 0; }\n"


def _compile(tmp_path, name: str, src: str, *extra: str) -> str:
    csrc = tmp_path / f"{name}.c"
    csrc.write_text(src)
    out = tmp_path / name
    subprocess.run(
        ["gcc", "-fno-stack-protector", "-no-pie", *extra, "-o", str(out), str(csrc)],
        check=True,
        capture_output=True,
    )
    return str(out)


@pytest.fixture()
def vuln_binary(tmp_path):
    return _compile(tmp_path, "vuln", _VULN_SRC)


def test_confirms_return_offset_72(vuln_binary):
    result = confirm_return_offset(vuln_binary, pattern_length=400)
    assert result.confirmed is True
    assert result.offset == 72
    assert result.verification == "verified"
    assert result.method in {"rip", "stack_return_slot"}
    assert result.observation.crashed is True
    assert result.observation.signal_name == "SIGSEGV"
    assert result.evidence  # 근거 비어 있지 않음


def test_offset_72_under_o2(tmp_path):
    binary = _compile(tmp_path, "vuln_o2", _VULN_SRC, "-O2")
    result = confirm_return_offset(binary, pattern_length=400)
    assert result.confirmed is True
    assert result.offset == 72


def test_no_crash_returns_unverified(tmp_path):
    binary = _compile(tmp_path, "safe", _SAFE_SRC)
    result = confirm_return_offset(binary, pattern_length=64)
    assert result.confirmed is False
    assert result.offset is None
    assert result.verification == "unverified"
    assert result.observation.crashed is False


def test_wall_clock_timeout_kills_process(tmp_path):
    binary = _compile(tmp_path, "hang", _HANG_SRC)
    result = confirm_return_offset(
        binary,
        pattern_length=64,
        limits=SandboxLimits(wall_seconds=1.0, cpu_seconds=2),
    )
    assert result.confirmed is False
    assert result.observation.timed_out is True


def test_run_with_input_observation_shape(vuln_binary):
    from pwnable_lab.payload.cyclic import cyclic

    observation = run_with_input(vuln_binary, cyclic(400) + b"\n")
    assert observation.crashed is True
    assert observation.rsp is not None
    assert observation.stack_words  # 최소 한 개 이상 PEEK 성공
    payload = observation.as_dict()
    assert payload["signal_name"] == "SIGSEGV"
    assert payload["rsp_hex"].startswith("0x")


def test_limits_validate_rejects_bad_values():
    SandboxLimits().validate()  # 기본값은 유효
    with pytest.raises(SandboxError):
        SandboxLimits(wall_seconds=0).validate()
    with pytest.raises(SandboxError):
        SandboxLimits(stack_peek_words=0).validate()
    with pytest.raises(SandboxError):
        SandboxLimits(capture_stdout_bytes=-1).validate()
    with pytest.raises(SandboxError):
        SandboxLimits(shell_settle_seconds=-0.1).validate()


def test_missing_binary_raises_sandbox_error():
    with pytest.raises(SandboxError):
        run_with_input("/nonexistent/path/binary", b"x\n")


def test_short_pattern_rejected(vuln_binary):
    with pytest.raises(SandboxError):
        confirm_return_offset(vuln_binary, pattern_length=4)
