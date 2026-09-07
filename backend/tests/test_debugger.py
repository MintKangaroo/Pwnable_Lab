"""ptrace 대화형 디버그 세션(Phase 6B): 브레이크포인트·스텝·레지스터/메모리 조회."""

from __future__ import annotations

import platform
import shutil
import subprocess

import pytest

from pwnable_lab.api.services import AnalysisService
from pwnable_lab.config import Settings
from pwnable_lab.elf.parser import parse_elf
from pwnable_lab.sandbox import SandboxLimits
from pwnable_lab.sandbox.debugger import DebugSession, DebugWorker, run_debug_script

_SUPPORTED = platform.system() == "Linux" and platform.machine() in {"x86_64", "AMD64"}
_HAVE_GCC = shutil.which("gcc") is not None

# add(a,b): 인자 레지스터(rdi/rsi) 관측용. greet(): stdin read → stdout write.
_SRC = """
#include <stdio.h>
#include <unistd.h>
int add(int a, int b){ return a + b; }
void greet(void){ char buf[64]; read(0, buf, 60); printf("hi\\n"); }
int main(void){ setvbuf(stdout, 0, 2, 0); int r = add(3, 4); greet(); return r; }
"""

# 널 역참조로 SIGSEGV 를 내는 크래시용 소스.
_CRASH_SRC = """
int main(void){ volatile int *p = 0; return *p; }
"""

_gated = pytest.mark.skipif(
    not (_SUPPORTED and _HAVE_GCC), reason="Linux/x86-64 + gcc 필요(실제 실행)"
)


def _compile(tmp_path, *, pie: bool = False, src: str = _SRC, name: str = "dbg") -> str:
    csrc = tmp_path / f"{name}.c"
    csrc.write_text(src)
    out = tmp_path / name
    flags = ["-fno-stack-protector", "-O0", "-pie" if pie else "-no-pie"]
    subprocess.run(
        ["gcc", *flags, "-o", str(out), str(csrc)],
        check=True,
        capture_output=True,
    )
    return str(out)


def _sym(path: str, name: str) -> int:
    img = parse_elf(open(path, "rb").read())
    s = img.symbol(name)
    assert s is not None and s.addr, f"{name} 심볼을 찾지 못했습니다"
    return int(s.addr)


@_gated
def test_breakpoint_hit_exposes_argument_registers(tmp_path):
    path = _compile(tmp_path)
    add = _sym(path, "add")
    with DebugSession(path, limits=SandboxLimits()) as s:
        assert s.set_breakpoint(add) is True
        ev = s.cont()
        assert ev.reason == "breakpoint"
        assert ev.rip == add and ev.breakpoint == add
        regs = s.registers()
        # add(3, 4) → rdi=a, rsi=b (SysV amd64 정수 인자).
        assert regs["rdi"] == 3
        assert regs["rsi"] == 4


@_gated
def test_step_advances_rip(tmp_path):
    path = _compile(tmp_path)
    add = _sym(path, "add")
    with DebugSession(path) as s:
        s.set_breakpoint(add)
        s.cont()
        before = s.registers()["rip"]
        ev = s.step()
        assert ev.reason == "step"
        assert s.registers()["rip"] != before


@_gated
def test_read_memory_masks_breakpoint_bytes(tmp_path):
    path = _compile(tmp_path)
    add = _sym(path, "add")
    with DebugSession(path) as s:
        s.set_breakpoint(add)
        s.cont()
        # 브레이크포인트가 걸려 있어도(0xCC) 원래 바이트로 가려 보여줘야 한다.
        mem = s.read_memory(add, 4)
        assert mem[0] != 0xCC


@_gated
def test_stack_returns_words(tmp_path):
    path = _compile(tmp_path)
    add = _sym(path, "add")
    with DebugSession(path) as s:
        s.set_breakpoint(add)
        s.cont()
        words = s.stack(4)
        assert len(words) >= 1
        # add 진입 직후 [RSP] 는 main 으로의 반환 주소(코드 영역).
        assert all(isinstance(a, int) and isinstance(v, int) for a, v in words)


@_gated
def test_continue_to_exit_reports_code_and_output(tmp_path):
    path = _compile(tmp_path)
    with DebugSession(path) as s:
        # 입력을 미리 넣어두고 종료까지 계속(add 는 3+4=7 반환 → exit code 7).
        s.send_input(b"AAAA\n")
        ev = s.cont()
        assert ev.reason == "exited"
        assert ev.exit_code == 7
        assert b"hi\n" in s.read_output()


@_gated
def test_run_debug_script_batch(tmp_path):
    path = _compile(tmp_path)
    add = _sym(path, "add")
    result = run_debug_script(
        path,
        [
            {"op": "break", "addr": add},
            {"op": "continue"},
            {"op": "registers"},
            {"op": "read", "addr": add, "length": 4},
            {"op": "input", "data": "AAAA\n"},
            {"op": "continue"},
            {"op": "output"},
            {"op": "bogus"},
        ],
    )
    ops = [s["op"] for s in result["steps"]]
    assert ops == [
        "break",
        "continue",
        "registers",
        "read",
        "input",
        "continue",
        "output",
        "bogus",
    ]
    assert "hi\n" in result["steps"][6]["output"]
    cont1 = result["steps"][1]
    assert cont1["reason"] == "breakpoint"
    regs = result["steps"][2]["registers"]
    assert regs["rdi"] == "0x3" and regs["rsi"] == "0x4"
    assert result["steps"][3]["hex"][:2] != "cc"  # 브레이크포인트 마스킹
    assert result["steps"][5]["reason"] == "exited"
    assert result["steps"][7]["error"] == "unknown-op"
    assert "hi\n" in result["output"]
    assert result["alive"] is False


@_gated
def test_service_debug_script_gated(tmp_path):
    path = _compile(tmp_path)
    add = _sym(path, "add")
    service = AnalysisService(Settings(sandbox_execution_enabled=True))
    result = service.debug_script(
        open(path, "rb").read(),
        [{"op": "break", "addr": add}, {"op": "continue"}, {"op": "registers"}],
    )
    assert result["steps"][1]["reason"] == "breakpoint"
    assert result["steps"][2]["registers"]["rdi"] == "0x3"


@_gated
def test_remove_breakpoint_lets_execution_continue(tmp_path):
    path = _compile(tmp_path)
    add = _sym(path, "add")
    with DebugSession(path) as s:
        s.set_breakpoint(add)
        s.cont()
        assert s.remove_breakpoint(add) is True
        assert s.remove_breakpoint(add) is False  # 이미 제거됨
        # 브레이크포인트 제거 후 계속하면 (입력 공급 후) 종료까지 간다.
        s.send_input(b"AAAA\n")
        ev = s.cont()
        assert ev.reason == "exited"


@_gated
def test_signal_crash_is_reported(tmp_path):
    path = _compile(tmp_path, src=_CRASH_SRC, name="crash")
    with DebugSession(path) as s:
        ev = s.cont()
        assert ev.reason == "signal"
        assert ev.signal_name == "SIGSEGV"
        assert ev.as_dict()["signal_name"] == "SIGSEGV"


@_gated
def test_pie_base_and_rebased_breakpoint(tmp_path):
    path = _compile(tmp_path, pie=True, name="dbg_pie")
    add_off = _sym(path, "add")  # PIE 는 base 상대 오프셋.
    with DebugSession(path, disable_aslr=True) as s:
        base = s.base()
        assert base is not None and base > 0
        assert s.set_breakpoint(base + add_off) is True
        ev = s.cont()
        assert ev.reason == "breakpoint"
        assert s.registers()["rdi"] == 3


@_gated
def test_run_debug_script_base_stack_unbreak_ops(tmp_path):
    path = _compile(tmp_path, pie=True, name="dbg_pie2")
    add_off = _sym(path, "add")
    # 먼저 base 를 관측해 절대 주소를 계산(배치 스크립트는 절대 주소를 받는다).
    with DebugSession(path, disable_aslr=True) as probe:
        base = probe.base()
    assert base is not None
    result = run_debug_script(
        path,
        [
            {"op": "base"},
            {"op": "break", "addr": base + add_off},
            {"op": "continue"},
            {"op": "stack", "count": 3},
            {"op": "unbreak", "addr": base + add_off},
        ],
    )
    assert result["steps"][0]["base"] is not None
    assert result["steps"][2]["reason"] == "breakpoint"
    assert len(result["steps"][3]["words"]) >= 1
    assert result["steps"][4]["ok"] is True


@_gated
def test_registers_after_exit_raises(tmp_path):
    from pwnable_lab.errors import SandboxError

    path = _compile(tmp_path)
    with DebugSession(path) as s:
        s.send_input(b"AAAA\n")
        s.cont()  # 종료까지.
        with pytest.raises(SandboxError):
            s.registers()
        # 종료된 세션에 브레이크포인트/입력은 무해하게 무시된다.
        assert s.set_breakpoint(0x401176) is False
        s.send_input(b"x")  # 예외 없이 무시.


@_gated
def test_debug_worker_relays_commands_on_dedicated_thread(tmp_path):
    path = _compile(tmp_path)
    add = _sym(path, "add")
    worker = DebugWorker(path, limits=SandboxLimits())
    try:
        assert worker.ready["event"] == "ready"
        assert worker.execute({"op": "break", "addr": add})["ok"] is True
        assert worker.execute({"op": "continue"})["reason"] == "breakpoint"
        regs = worker.execute({"op": "registers"})["registers"]
        assert regs["rdi"] == "0x3"
        assert worker.execute({"op": "bogus"})["error"] == "unknown-op"
        worker.execute({"op": "input", "data": "AAAA\n"})
        assert worker.execute({"op": "continue"})["reason"] == "exited"
    finally:
        worker.close()
    # 종료 후 execute 는 무해하게 closed 를 반환한다.
    assert worker.execute({"op": "registers"})["event"] == "closed"


@_gated
def test_debug_worker_reports_session_error(tmp_path):
    worker = DebugWorker(str(tmp_path / "nope"), limits=SandboxLimits())
    try:
        assert worker.ready["event"] == "error"
    finally:
        worker.close()


@_gated
def test_debug_session_edge_cases(tmp_path):
    from pwnable_lab.errors import SandboxError

    path = _compile(tmp_path)
    add = _sym(path, "add")
    s = DebugSession(path)
    try:
        # 메모리 읽기 경계: 0 바이트 → 빈 결과, 음수 → 예외.
        assert s.read_memory(add, 0) == b""
        with pytest.raises(SandboxError):
            s.read_memory(add, -1)
        # 같은 주소에 두 번 브레이크포인트 → 두 번째도 True(멱등).
        assert s.set_breakpoint(add) is True
        assert s.set_breakpoint(add) is True
        s.cont()
        assert s.read_memory(add, 2)  # 유효 메모리(브레이크포인트 마스킹 경로).
    finally:
        s.close()
    # 종료 후: base 는 None, send_input 은 무해, 재종료도 안전(멱등).
    assert s.base() is None
    s.send_input(b"x")
    s.close()


def test_debug_session_missing_binary(tmp_path):
    from pwnable_lab.errors import SandboxError

    if not _SUPPORTED:
        pytest.skip("Linux/x86-64 필요")
    with pytest.raises(SandboxError):
        DebugSession(str(tmp_path / "nope"))
