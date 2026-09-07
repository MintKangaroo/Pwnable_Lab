"""프로세스 메모리 덤프(Phase 6D): 지정 시점의 매핑 영역 바이트·엔트로피 스냅샷."""

from __future__ import annotations

import platform
import shutil
import subprocess

import pytest

from pwnable_lab.api.services import AnalysisService
from pwnable_lab.config import Settings
from pwnable_lab.elf.parser import parse_elf
from pwnable_lab.sandbox import SandboxLimits
from pwnable_lab.sandbox.memdump import dump_memory

_SUPPORTED = platform.system() == "Linux" and platform.machine() in {"x86_64", "AMD64"}
_HAVE_GCC = shutil.which("gcc") is not None

_PLAIN = b"PWNPILOT_MEMDUMP_SECRET"

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
    csrc = tmp_path / "md.c"
    csrc.write_text(_source())
    out = tmp_path / "md"
    subprocess.run(
        ["gcc", "-no-pie", "-O0", "-o", str(out), str(csrc)],
        check=True,
        capture_output=True,
    )
    return str(out)


def _checkpoint(path: str) -> int:
    return int(parse_elf(open(path, "rb").read()).symbol("checkpoint").addr)


def test_bad_select_rejected(tmp_path):
    # select 검증은 실행 전에 이뤄지므로 gcc 없이도 확인 가능.
    path = str(tmp_path / "nope")
    (tmp_path / "nope").write_bytes(b"\x7fELF")
    result = dump_memory(path, select="bogus")
    assert result["attempted"] is False
    assert result["reason"].startswith("bad-select")


@_gated
def test_dump_captures_decoded_secret_bytes(tmp_path):
    path = _compile(tmp_path)
    result = dump_memory(
        path, breakpoint=_checkpoint(path), select="writable", limits=SandboxLimits()
    )
    assert result["attempted"] is True
    assert result["stopped"]["reason"] == "breakpoint"
    assert result["region_count"] >= 1
    assert result["captured_bytes"] > 0
    # 복호화된 시크릿 바이트가 쓰기 가능 영역 덤프에 있어야 한다.
    needle = _PLAIN.hex()
    assert any(needle in r.get("hex", "") for r in result["regions"])
    # 각 영역은 sha256·엔트로피 메타데이터를 갖는다.
    for r in result["regions"]:
        assert r["sha256"] and r["entropy"] is not None


@_gated
def test_select_code_only_returns_executable(tmp_path):
    path = _compile(tmp_path)
    result = dump_memory(
        path, breakpoint=_checkpoint(path), select="code", limits=SandboxLimits()
    )
    assert result["attempted"] is True
    assert all("x" in r["perms"] for r in result["regions"])


@_gated
def test_steps_mode_and_select_all(tmp_path):
    # 브레이크포인트 없이 N 스텝 뒤 모든 읽기 가능 매핑을 덤프(steps 경로 + all 선택자).
    path = _compile(tmp_path)
    result = dump_memory(path, steps=30, select="all", limits=SandboxLimits())
    assert result["attempted"] is True
    assert result["stopped"]["reason"] in {"step", "exited", "exec-stop"}
    assert result["region_count"] >= 1
    # all 은 실행 전용 코드와 쓰기 가능 데이터를 모두 포함할 수 있다.
    perms = {r["perms"] for r in result["regions"]}
    assert perms  # 최소 한 영역


@_gated
def test_service_memdump_gated(tmp_path):
    path = _compile(tmp_path)
    service = AnalysisService(Settings(sandbox_execution_enabled=True))
    result = service.dump_memory(
        open(path, "rb").read(), breakpoint=_checkpoint(path), select="writable"
    )
    assert result["attempted"] is True
    assert any(_PLAIN.hex() in r.get("hex", "") for r in result["regions"])
