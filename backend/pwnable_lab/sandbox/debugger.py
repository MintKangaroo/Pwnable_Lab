"""ptrace 기반 대화형 디버그 세션 (Phase 6B — GDB/MI 대체 코어).

로드맵의 "GDB/MI interactive debugger" 를 **외부 gdb 없이** 자체 ptrace 러너
(:mod:`sandbox.runner`) 위에 구현한다. gdb 는 이 프로젝트의 어느 경로에도 필요치
않으며(자동 익스 전체가 ctypes ptrace 로 브레이크포인트·레지스터·단일스텝을 이미
구현), 그 코어를 **지속 세션**으로 노출해 브레이크포인트·연속/스텝 실행·레지스터/메모리
조회를 명령 단위로 수행할 수 있게 한다.

:class:`DebugSession` 은 대상 바이너리를 ``PTRACE_TRACEME`` 로 fork·execv 해 첫
exec-stop 에 정지시킨 뒤 살아 있는 트레이시(tracee)를 유지한다. 각 메서드는 **세션을
시작한 같은 스레드에서** 호출해야 한다(ptrace 는 트레이서 스레드에 고정). WebSocket
인터랙티브 디버거(후속 증분)는 이 세션 객체를 스레드에 태워 명령을 중계하면 된다.

소프트웨어 브레이크포인트는 대상 주소의 첫 바이트를 ``0xCC``(int3)로 덮고 원래
바이트를 보관한다. 히트 시 SIGTRAP 이 뜨고 RIP 은 ``bp+1`` 을 가리키므로, 원래
바이트를 복원하고 RIP 을 ``bp`` 로 되돌린다. 그 브레이크포인트를 지나 계속하려면
원래 명령을 한 번 단일스텝한 뒤 다시 ``0xCC`` 로 재무장한다(표준 기법).

.. warning::
   신뢰할 수 없는 바이너리를 **실행**한다. :mod:`sandbox.runner` 와 동일하게 자원
   상한·프로세스그룹 종료만 강제하므로, 프로덕션에서는 network-disabled 일회용
   컨테이너 경계 안에서만 호출해야 한다(서비스 계층이 게이트를 강제).
"""

from __future__ import annotations

import ctypes
import errno
import os
import signal
import time
from dataclasses import dataclass, field

from pwnable_lab.errors import SandboxError
from pwnable_lab.sandbox.runner import (
    SandboxLimits,
    _apply_child_limits,
    _disable_aslr,
    _kill_group,
    _libc,
    _read_pie_base,
    _require_supported_platform,
)

# ptrace 요청 상수 (Linux/x86-64)
_PTRACE_TRACEME = 0
_PTRACE_PEEKTEXT = 1
_PTRACE_POKETEXT = 4
_PTRACE_CONT = 7
_PTRACE_SINGLESTEP = 9
_PTRACE_GETREGS = 12
_PTRACE_SETREGS = 13

_WORD = 8
_INT3 = 0xCC

# x86-64 user_regs_struct 의 27개 unsigned long 필드 순서.
_REG_NAMES = [
    "r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8",
    "rax", "rcx", "rdx", "rsi", "rdi", "orig_rax", "rip", "cs", "eflags",
    "rsp", "ss", "fs_base", "gs_base", "ds", "es", "fs", "gs",
]  # fmt: skip
_REG_COUNT = len(_REG_NAMES)


@dataclass
class StopEvent:
    """트레이시가 멈춘(또는 종료된) 사건 하나."""

    reason: str  # "exec-stop" | "breakpoint" | "step" | "signal" | "exited" | "timeout"
    rip: int | None = None
    signal: int | None = None
    signal_name: str | None = None
    exit_code: int | None = None
    breakpoint: int | None = None  # 히트한 알려진 브레이크포인트 주소.

    def as_dict(self) -> dict:
        return {
            "reason": self.reason,
            "rip": None if self.rip is None else f"0x{self.rip:x}",
            "signal": self.signal,
            "signal_name": self.signal_name,
            "exit_code": self.exit_code,
            "breakpoint": None if self.breakpoint is None else f"0x{self.breakpoint:x}",
        }


@dataclass
class DebugSession:
    """살아 있는 ptrace 트레이시에 대한 지속 디버그 세션.

    ``binary_path`` 를 fork·execv 해 첫 exec-stop 에 정지시킨다. ``disable_aslr`` 면
    PIE 로드 base 가 결정적(관측·재현 가능)이다. stdin 은 세션이 쥔 파이프에서 오고
    (``send_input``), stdout/stderr 는 논블로킹으로 버퍼에 모은다(``read_output``).
    """

    binary_path: str
    limits: SandboxLimits = field(default_factory=SandboxLimits)
    disable_aslr: bool = True

    def __post_init__(self) -> None:
        _require_supported_platform()
        self.limits.validate()
        if not os.path.isfile(self.binary_path):
            raise SandboxError(f"실행 대상 파일이 없습니다: {self.binary_path}")

        self._lib = _libc()
        self._breakpoints: dict[int, int] = {}  # addr -> 원래 바이트
        self._at_breakpoint: int | None = None  # 현재 정지한 브레이크포인트 주소.
        self._output = bytearray()
        self._alive = True
        self._exit_code: int | None = None

        in_r, in_w = os.pipe()
        out_r, out_w = os.pipe()
        self._stdin_w = in_w
        self._stdout_r = out_r
        os.set_blocking(out_r, False)

        pid = os.fork()
        if pid == 0:  # pragma: no cover - 자식 프로세스
            try:
                os.setsid()
                os.dup2(in_r, 0)
                os.dup2(out_w, 1)
                os.dup2(out_w, 2)
                for fd in (in_r, in_w, out_r, out_w):
                    os.close(fd)
                if self.disable_aslr:
                    _disable_aslr()
                _apply_child_limits(self.limits)
                self._lib.ptrace(_PTRACE_TRACEME, 0, None, None)
                os.execv(self.binary_path, [self.binary_path])
            except BaseException:
                os._exit(127)
            os._exit(127)

        self._pid = pid
        os.close(in_r)
        os.close(out_w)
        self._deadline = time.monotonic() + self.limits.wall_seconds
        # 첫 exec-stop 까지 대기(새 이미지가 매핑돼 base/브레이크포인트 설정 가능).
        first = self._wait()
        if first.reason not in {"exec-stop", "signal", "breakpoint", "step"}:
            self.close()
            raise SandboxError(
                f"디버그 대상이 exec 정지에 도달하지 못했습니다: {first.reason}"
            )

    # --- 상태 조회 ---------------------------------------------------------

    def base(self) -> int | None:
        """PIE 로드 base(``/proc/<pid>/maps`` 관측). 비 PIE 면 None 일 수 있다."""

        if not self._alive:
            return None
        return _read_pie_base(self._pid, self.binary_path)

    def registers(self) -> dict[str, int]:
        """현재 레지스터 전체를 이름→값 dict 로."""

        if not self._alive:
            raise SandboxError("트레이시가 이미 종료됐습니다.")
        return self._get_regs()

    def read_memory(self, addr: int, length: int) -> bytes:
        """``addr`` 부터 ``length`` 바이트를 읽는다(PEEKTEXT, 워드 단위).

        gdb 처럼 우리가 심은 브레이크포인트(``0xCC``) 바이트는 저장해 둔 **원래
        바이트로 가려** 반환한다(디버거의 자기 흔적이 메모리 덤프에 안 보이게).
        """

        if length < 0:
            raise SandboxError("length 는 0 이상이어야 합니다.")
        if length == 0:
            return b""
        start = addr - (addr % _WORD)
        end = addr + length
        out = bytearray()
        cur = start
        while cur < end:
            word = self._peek(cur)
            if word is None:
                break
            out += int(word).to_bytes(_WORD, "little")
            cur += _WORD
        # 브레이크포인트 바이트를 원래 값으로 되돌려 보여준다.
        for bp_addr, orig in self._breakpoints.items():
            if start <= bp_addr < start + len(out):
                out[bp_addr - start] = orig
        off = addr - start
        return bytes(out[off : off + length])

    def stack(self, count: int | None = None) -> list[tuple[int, int]]:
        """``[RSP]`` 부터 위로 읽은 스택 워드 ``(주소, 값)`` 목록."""

        count = count or self.limits.stack_peek_words
        rsp = self._get_regs()["rsp"]
        words: list[tuple[int, int]] = []
        for i in range(count):
            word = self._peek(rsp + i * _WORD)
            if word is None:
                break
            words.append((rsp + i * _WORD, word & 0xFFFFFFFFFFFFFFFF))
        return words

    @property
    def pid(self) -> int:
        """트레이시 프로세스 ID."""

        return self._pid

    def maps(self) -> list[dict]:
        """읽기 가능한 메모리 매핑 목록(``/proc/<pid>/maps``).

        각 항목은 ``{start, end, perms, path}``. 런타임 strings 처럼 실행 중 메모리를
        훑는 도구가 사용한다. 트레이시가 없으면 빈 목록.
        """

        if not self._alive:
            return []
        regions: list[dict] = []
        try:
            with open(f"/proc/{self._pid}/maps") as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) < 5 or "r" not in parts[1]:
                        continue
                    start_s, _, end_s = parts[0].partition("-")
                    path = parts[5] if len(parts) >= 6 else ""
                    regions.append(
                        {
                            "start": int(start_s, 16),
                            "end": int(end_s, 16),
                            "perms": parts[1],
                            "path": path,
                        }
                    )
        except OSError:
            return []
        return regions

    def read_region(self, start: int, size: int) -> bytes:
        """``/proc/<pid>/mem`` 에서 한 번에 읽는다(정지 상태, PEEK 보다 빠름).

        읽기 실패(권한 없는 영역 등)는 짧거나 빈 바이트로 반환한다.
        """

        if not self._alive or size <= 0:
            return b""
        try:
            fd = os.open(f"/proc/{self._pid}/mem", os.O_RDONLY)
        except OSError:
            return b""
        try:
            return os.pread(fd, size, start)
        except OSError:
            return b""
        finally:
            os.close(fd)

    # --- 브레이크포인트 ----------------------------------------------------

    def set_breakpoint(self, addr: int) -> bool:
        """``addr`` 에 소프트웨어 브레이크포인트(int3)를 건다. 성공 여부 반환."""

        if not self._alive:
            return False
        if addr in self._breakpoints:
            return True
        word = self._peek(addr)
        if word is None:
            return False
        orig = word & 0xFF
        patched = (word & ~0xFF) | _INT3
        if not self._poke(addr, patched):
            return False
        self._breakpoints[addr] = orig
        return True

    def remove_breakpoint(self, addr: int) -> bool:
        """``addr`` 의 브레이크포인트를 제거(원래 바이트 복원)."""

        if addr not in self._breakpoints:
            return False
        if self._alive:
            word = self._peek(addr)
            if word is not None:
                self._poke(addr, (word & ~0xFF) | self._breakpoints[addr])
        del self._breakpoints[addr]
        if self._at_breakpoint == addr:
            self._at_breakpoint = None
        return True

    # --- 실행 제어 ---------------------------------------------------------

    def cont(self) -> StopEvent:
        """다음 브레이크포인트/시그널/종료까지 실행을 계속한다."""

        return self._resume(_PTRACE_CONT)

    def step(self) -> StopEvent:
        """기계어 한 명령을 단일 실행한다."""

        return self._resume(_PTRACE_SINGLESTEP)

    def send_input(self, data: bytes) -> None:
        """트레이시의 stdin 으로 바이트를 보낸다(대화형 입력)."""

        if not self._alive:
            return
        try:
            os.write(self._stdin_w, data)
        except OSError:
            pass

    def read_output(self) -> bytes:
        """지금까지 누적된 트레이시 stdout/stderr 를 반환한다(비파괴)."""

        self._drain_output()
        return bytes(self._output[: self.limits.capture_stdout_bytes])

    def close(self) -> None:
        """트레이시를 종료하고 세션 자원을 정리한다(idempotent)."""

        if getattr(self, "_pid", None) and self._alive:
            _kill_group(self._pid, timed_out=False, note=None)
        self._alive = False
        for attr in ("_stdin_w", "_stdout_r"):
            fd = getattr(self, attr, None)
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
                setattr(self, attr, None)

    def __enter__(self) -> DebugSession:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # --- 내부 ptrace 도우미 -----------------------------------------------

    def _resume(self, request: int) -> StopEvent:
        if not self._alive:
            return StopEvent(reason="exited", exit_code=self._exit_code)
        # 브레이크포인트 위에 정지 중이면: 원래 명령을 스텝한 뒤 재무장하고 계속한다.
        if self._at_breakpoint is not None:
            bp = self._at_breakpoint
            self._at_breakpoint = None
            orig = self._breakpoints.get(bp)
            if orig is not None:
                word = self._peek(bp)
                if word is not None:
                    self._poke(bp, (word & ~0xFF) | orig)  # 원래 바이트 복원
                stepped = self._single_step_raw()
                if not self._alive:
                    return stepped
                word = self._peek(bp)
                if word is not None:
                    self._poke(bp, (word & ~0xFF) | _INT3)  # 재무장
                if request == _PTRACE_SINGLESTEP:
                    return stepped
        self._lib.ptrace(request, self._pid, None, None)
        return self._wait()

    def _single_step_raw(self) -> StopEvent:
        self._lib.ptrace(_PTRACE_SINGLESTEP, self._pid, None, None)
        return self._wait()

    def _wait(self) -> StopEvent:
        """트레이시가 멈추거나 끝날 때까지 대기하고 StopEvent 를 만든다."""

        while True:
            if time.monotonic() > self._deadline:
                self.close()
                return StopEvent(reason="timeout")
            try:
                waited, status = os.waitpid(self._pid, os.WNOHANG)
            except ChildProcessError:
                self._alive = False
                return StopEvent(reason="exited", exit_code=self._exit_code)
            if waited == 0:
                time.sleep(0.002)
                continue
            self._drain_output()
            if os.WIFEXITED(status):
                self._alive = False
                self._exit_code = os.WEXITSTATUS(status)
                return StopEvent(reason="exited", exit_code=self._exit_code)
            if os.WIFSIGNALED(status):
                self._alive = False
                sig = os.WTERMSIG(status)
                return StopEvent(reason="signal", signal=sig, signal_name=_signame(sig))
            if os.WIFSTOPPED(status):
                return self._on_stop(os.WSTOPSIG(status))
            time.sleep(0.002)

    def _on_stop(self, sig: int) -> StopEvent:
        regs = self._get_regs()
        rip = regs["rip"]
        if sig == signal.SIGTRAP:
            # 브레이크포인트 히트: RIP 은 bp+1 → 원래 바이트 복원 위치로 되돌린다.
            bp = rip - 1
            if bp in self._breakpoints:
                regs["rip"] = bp
                self._set_regs(regs)
                self._at_breakpoint = bp
                return StopEvent(reason="breakpoint", rip=bp, breakpoint=bp)
            # int3 아닌 SIGTRAP: exec-stop(첫 정지) 또는 단일스텝 완료.
            reason = "exec-stop" if not self._breakpoints else "step"
            return StopEvent(reason=reason, rip=rip)
        return StopEvent(
            reason="signal", rip=rip, signal=sig, signal_name=_signame(sig)
        )

    def _get_regs(self) -> dict[str, int]:
        regs = (ctypes.c_ulong * _REG_COUNT)()
        rc = self._lib.ptrace(_PTRACE_GETREGS, self._pid, None, ctypes.addressof(regs))
        if rc != 0:
            raise SandboxError("PTRACE_GETREGS 실패")
        return {name: int(regs[i]) for i, name in enumerate(_REG_NAMES)}

    def _set_regs(self, values: dict[str, int]) -> None:
        regs = (ctypes.c_ulong * _REG_COUNT)()
        for i, name in enumerate(_REG_NAMES):
            regs[i] = ctypes.c_ulong(values[name] & 0xFFFFFFFFFFFFFFFF)
        self._lib.ptrace(_PTRACE_SETREGS, self._pid, None, ctypes.addressof(regs))

    def _peek(self, addr: int) -> int | None:
        ctypes.set_errno(0)
        value = self._lib.ptrace(
            _PTRACE_PEEKTEXT, self._pid, ctypes.c_void_p(addr), None
        )
        if ctypes.get_errno() != 0:
            return None
        return int(value) & 0xFFFFFFFFFFFFFFFF

    def _poke(self, addr: int, word: int) -> bool:
        ctypes.set_errno(0)
        rc = self._lib.ptrace(
            _PTRACE_POKETEXT,
            self._pid,
            ctypes.c_void_p(addr),
            ctypes.c_void_p(word & 0xFFFFFFFFFFFFFFFF),
        )
        return rc == 0 and ctypes.get_errno() == 0

    def _drain_output(self) -> None:
        fd = self._stdout_r
        if fd is None:
            return
        while len(self._output) < self.limits.capture_stdout_bytes:
            try:
                chunk = os.read(fd, 4096)
            except BlockingIOError:
                break
            except OSError as exc:
                if exc.errno == errno.EAGAIN:
                    break
                break
            if not chunk:
                break
            self._output += chunk


def _signame(sig: int) -> str:
    try:
        return signal.Signals(sig).name
    except ValueError:  # pragma: no cover - 방어적
        return f"SIG{sig}"


# 배치 디버그 스크립트 지원 명령(HTTP/CLI 로 노출 가능한 무상태 형태).
_SCRIPT_OPS = {
    "base",
    "break",
    "unbreak",
    "continue",
    "step",
    "registers",
    "read",
    "stack",
    "input",
    "output",
}


def run_debug_script(
    binary_path: str,
    commands: list[dict],
    *,
    limits: SandboxLimits | None = None,
    disable_aslr: bool = True,
) -> dict:
    """디버그 명령 목록을 한 세션에서 순서대로 실행하고 구조화 결과를 반환한다.

    WebSocket 라이브 디버거(후속 증분)가 없이도 프로그래밍적으로 디버깅할 수 있는
    무상태 배치 형태다. 각 ``commands`` 항목은 ``{"op": ...}`` dict 다:

    - ``base``: PIE 로드 base(hex 또는 null)
    - ``break`` / ``unbreak`` (``addr``): 브레이크포인트 설정/제거(절대 주소)
    - ``continue`` / ``step``: 실행 제어 → StopEvent
    - ``registers``: 레지스터 전체(이름→hex)
    - ``read`` (``addr``, ``length``): 메모리 hex
    - ``stack`` (``count``?): 스택 워드
    - ``input`` (``data``): 트레이시 stdin 으로 문자열 주입

    주소는 절대 주소로 해석한다(PIE 는 먼저 ``base`` 로 관측한 값을 더해 계산).
    반환: ``{"steps": [{op, ...}], "output": str, "alive": bool}``.
    """

    limits = limits or SandboxLimits()
    steps: list[dict] = []
    session = DebugSession(binary_path, limits=limits, disable_aslr=disable_aslr)
    try:
        for cmd in commands:
            op = cmd.get("op")
            if op not in _SCRIPT_OPS:
                steps.append({"op": op, "error": "unknown-op"})
                continue
            steps.append(_run_one(session, op, cmd))
        output = session.read_output().decode("utf-8", "replace")
        alive = session._alive
    finally:
        session.close()
    return {"steps": steps, "output": output, "alive": alive}


def _run_one(session: DebugSession, op: str, cmd: dict) -> dict:
    if op == "base":
        base = session.base()
        return {"op": op, "base": None if base is None else f"0x{base:x}"}
    if op == "break":
        return {
            "op": op,
            "addr": _hx(cmd["addr"]),
            "ok": session.set_breakpoint(int(cmd["addr"])),
        }
    if op == "unbreak":
        return {
            "op": op,
            "addr": _hx(cmd["addr"]),
            "ok": session.remove_breakpoint(int(cmd["addr"])),
        }
    if op == "continue":
        return {"op": op, **session.cont().as_dict()}
    if op == "step":
        return {"op": op, **session.step().as_dict()}
    if op == "registers":
        return {
            "op": op,
            "registers": {k: f"0x{v:x}" for k, v in session.registers().items()},
        }
    if op == "read":
        data = session.read_memory(int(cmd["addr"]), int(cmd["length"]))
        return {"op": op, "addr": _hx(cmd["addr"]), "hex": data.hex()}
    if op == "stack":
        words = session.stack(cmd.get("count"))
        return {"op": op, "words": [[f"0x{a:x}", f"0x{v:x}"] for a, v in words]}
    if op == "output":
        return {"op": op, "output": session.read_output().decode("utf-8", "replace")}
    # op == "input"
    session.send_input(str(cmd.get("data", "")).encode())
    return {"op": op, "sent": True}


def _hx(value: int) -> str:
    return f"0x{int(value):x}"


class DebugWorker:
    """:class:`DebugSession` 을 **전용 스레드**에 태워 명령을 큐로 중계하는 래퍼.

    ptrace 는 트레이서 스레드에 고정되므로 세션의 모든 조작은 세션을 생성한 스레드
    하나에서만 해야 한다. WebSocket 핸들러는 async 이벤트 루프에서 도니, 세션을 이
    워커 스레드가 소유하게 하고 명령/결과를 :class:`queue.Queue` 로 주고받는다.

    ``ready`` 는 세션 생성 결과(``{"event": "ready"}`` 또는 ``{"event": "error",
    "error": ...}``)다. ``execute(cmd)`` 는 명령 하나를 워커 스레드에서 실행하고
    결과 dict 를 돌려준다. ``close`` 는 세션을 정리하고 스레드를 join 한다.
    ``cleanup_path`` 가 주어지면 종료 시 그 임시 파일을 지운다.
    """

    def __init__(
        self,
        binary_path: str,
        *,
        limits: SandboxLimits | None = None,
        disable_aslr: bool = True,
        cleanup_path: str | None = None,
    ) -> None:
        import queue
        import threading

        self._cmd_q: queue.Queue = queue.Queue()
        self._res_q: queue.Queue = queue.Queue()
        self._cleanup_path = cleanup_path
        self._closed = False
        self._thread = threading.Thread(
            target=self._run,
            args=(binary_path, limits or SandboxLimits(), disable_aslr),
            daemon=True,
        )
        self._thread.start()
        self.ready: dict = self._res_q.get()

    def _run(self, binary_path: str, limits: SandboxLimits, disable_aslr: bool) -> None:
        try:
            session = DebugSession(
                binary_path, limits=limits, disable_aslr=disable_aslr
            )
        except Exception as exc:  # 세션 생성 실패도 결과로 보고.
            self._res_q.put({"event": "error", "error": str(exc)})
            return
        self._res_q.put({"event": "ready"})
        try:
            while True:
                cmd = self._cmd_q.get()
                if cmd is None or cmd.get("op") == "close":
                    break
                op = cmd.get("op")
                if op not in _SCRIPT_OPS:
                    self._res_q.put({"op": op, "error": "unknown-op"})
                    continue
                try:
                    self._res_q.put(_run_one(session, op, cmd))
                except Exception as exc:  # 개별 명령 오류는 세션을 죽이지 않는다.
                    self._res_q.put({"op": op, "error": str(exc)})
        finally:
            session.close()
            self._res_q.put({"event": "closed"})

    def execute(self, cmd: dict) -> dict:
        if self._closed:
            return {"event": "closed"}
        self._cmd_q.put(cmd)
        result: dict = self._res_q.get()
        return result

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._cmd_q.put(None)
        self._thread.join(timeout=10.0)
        if self._cleanup_path:
            try:
                os.unlink(self._cleanup_path)
            except OSError:
                pass


__all__ = ["DebugSession", "DebugWorker", "StopEvent", "run_debug_script"]
