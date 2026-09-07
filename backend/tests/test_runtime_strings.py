"""런타임 strings(Phase 6C): 실행 중 메모리에서만 나타나는 복호화 문자열 발굴."""

from __future__ import annotations

import platform
import shutil
import subprocess

import pytest

from pwnable_lab.api.services import AnalysisService
from pwnable_lab.config import Settings
from pwnable_lab.elf.parser import parse_elf
from pwnable_lab.sandbox import SandboxLimits
from pwnable_lab.sandbox.runtime_strings import _ascii_runs, runtime_strings

_SUPPORTED = platform.system() == "Linux" and platform.machine() in {"x86_64", "AMD64"}
_HAVE_GCC = shutil.which("gcc") is not None

_PLAIN = b"PWNPILOT_RUNTIME_SECRET"

_gated = pytest.mark.skipif(
    not (_SUPPORTED and _HAVE_GCC), reason="Linux/x86-64 + gcc 필요(실제 실행)"
)


def _source() -> str:
    enc = bytes(c ^ 0x41 for c in _PLAIN)
    esc = "".join(f"\\x{b:02x}" for b in enc)
    return (
        "#include <stdio.h>\n"
        "char secret[64];\n"
        "void checkpoint(void){ }\n"
        'void reveal(void){ const char e[] = "' + esc + '"; int i;'
        f" for(i=0;i<{len(_PLAIN)};i++) secret[i]=e[i]^0x41; }}\n"
        "int main(void){ setvbuf(stdout,0,2,0); reveal(); checkpoint();"
        ' puts("done"); return 0; }\n'
    )


def _compile(tmp_path) -> str:
    csrc = tmp_path / "rts.c"
    csrc.write_text(_source())
    out = tmp_path / "rts"
    subprocess.run(
        ["gcc", "-no-pie", "-O0", "-o", str(out), str(csrc)],
        check=True,
        capture_output=True,
    )
    return str(out)


def test_ascii_runs_extracts_printable_runs():
    # 종료 널 없이 끝나는 런(tail1234)도 잡아야 한다(말미 처리 경로).
    blob = b"\x00\x01hello\x00ab\x00\x00world!\x00tail1234"
    runs = list(_ascii_runs(blob, 4))
    assert "hello" in runs
    assert "world!" in runs
    assert "tail1234" in runs
    assert "ab" not in runs  # min_length=4 미만


@_gated
def test_secret_is_absent_from_static_file(tmp_path):
    path = _compile(tmp_path)
    # 평문 시크릿은 파일(정적)에 없어야 한다(XOR 인코딩되어 저장됨).
    assert _PLAIN not in open(path, "rb").read()


@_gated
def test_runtime_strings_reveals_decoded_secret(tmp_path):
    path = _compile(tmp_path)
    checkpoint = parse_elf(open(path, "rb").read()).symbol("checkpoint").addr
    result = runtime_strings(path, breakpoint=checkpoint, limits=SandboxLimits())
    assert result["attempted"] is True
    assert result["stopped"]["reason"] == "breakpoint"
    assert result["scanned_bytes"] > 0
    # 정적에 없던 런타임 복호화 문자열이 발굴돼야 한다.
    assert any(_PLAIN.decode() in s for s in result["runtime_only"])


@_gated
def test_runtime_strings_steps_mode(tmp_path):
    # 브레이크포인트 없이 N 스텝 단일 실행 후 메모리 스캔(스텝 경로).
    path = _compile(tmp_path)
    result = runtime_strings(path, steps=30, limits=SandboxLimits())
    assert result["attempted"] is True
    assert result["stopped"]["reason"] in {"step", "exited", "signal", "exec-stop"}
    assert result["scanned_bytes"] >= 0


@_gated
def test_runtime_strings_breakpoint_unset_is_reported(tmp_path):
    path = _compile(tmp_path)
    # 잘못된(매핑 안 된) 주소에 브레이크포인트 → 실패 보고.
    result = runtime_strings(path, breakpoint=0x1, limits=SandboxLimits())
    assert result["attempted"] is False


@_gated
def test_service_runtime_strings_gated(tmp_path):
    path = _compile(tmp_path)
    checkpoint = parse_elf(open(path, "rb").read()).symbol("checkpoint").addr
    service = AnalysisService(Settings(sandbox_execution_enabled=True))
    result = service.runtime_strings(open(path, "rb").read(), breakpoint=checkpoint)
    assert result["attempted"] is True
    assert any(_PLAIN.decode() in s for s in result["runtime_only"])
