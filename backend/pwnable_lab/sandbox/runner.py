"""ptrace 기반 크래시 관측 및 오프셋 확정 러너 (x86-64/Linux).

핵심 아이디어
------------
스택 오버플로 오프셋을 정적으로 추론하는 대신(:func:`analyzer.strategy._infer_offset`
는 gcc 의 간접 버퍼 로드 관용구에서 실패한다), 대상 바이너리에 De Bruijn 순환
패턴을 주입해 실제로 크래시를 유발하고, 크래시 시점의 ``RIP`` 또는 반환 주소 슬롯
(``[RSP]``)에 실린 패턴 바이트를 :func:`payload.cyclic.cyclic_find` 로 역산해
**반환 주소까지의 정확한 오프셋을 확정**한다.

안전 경계
--------
* 자식 프로세스는 새 세션/프로세스그룹(:func:`os.setsid`)에서 실행되고, 실행 전
  ``RLIMIT_CPU``/``RLIMIT_AS``/``RLIMIT_NPROC``/``RLIMIT_FSIZE``/``RLIMIT_CORE`` 를
  건다. 부모는 wall-clock 데드라인을 두고 초과 시 프로세스그룹 전체를 ``SIGKILL``.
* 표준입력만 사용(비대화형). 네트워크/파일 생성은 rlimit 로 억제하되, 완전한
  네트워크 차단은 상위 컨테이너 경계의 책임이다(모듈 docstring 경고 참조).
* 크래시가 없거나 오프셋을 못 찾는 것은 예외가 아니라 관측 결과로 반환한다.
  :class:`~pwnable_lab.errors.SandboxError` 는 플랫폼 미지원·ptrace 구조적 실패에만.
"""

from __future__ import annotations

import ctypes
import os
import platform
import resource
import signal
import time
from dataclasses import dataclass, field

from pwnable_lab.errors import SandboxError
from pwnable_lab.payload.cyclic import cyclic, cyclic_find

# --- ptrace 상수 (Linux/x86-64) ---
_PTRACE_TRACEME = 0
_PTRACE_PEEKDATA = 2
_PTRACE_CONT = 7
_PTRACE_KILL = 8
_PTRACE_GETREGS = 12

# user_regs_struct(x86-64) 는 27개의 unsigned long. 필요한 필드의 인덱스만 사용.
_REG_COUNT = 27
_RIP_INDEX = 16
_RSP_INDEX = 19
_WORD = 8


@dataclass
class SandboxLimits:
    """자식 프로세스에 강제할 자원/시간 상한."""

    wall_seconds: float = 5.0
    cpu_seconds: int = 2
    address_space_bytes: int = 512 * 1024 * 1024
    max_processes: int = 64
    stack_peek_words: int = 8

    def validate(self) -> None:
        if self.wall_seconds <= 0 or self.cpu_seconds <= 0:
            raise SandboxError("시간 상한은 양수여야 합니다.")
        if self.stack_peek_words < 1:
            raise SandboxError("stack_peek_words 는 1 이상이어야 합니다.")


@dataclass
class CrashObservation:
    """단일 실행의 관측 결과. 크래시 없음도 유효한 결과다."""

    crashed: bool
    timed_out: bool
    signal: int | None
    signal_name: str | None
    rip: int | None
    rsp: int | None
    # [RSP] 부터 위쪽으로 읽은 스택 워드(주소, 값). ptrace PEEK 성공분만.
    stack_words: list[tuple[int, int]] = field(default_factory=list)
    exit_code: int | None = None
    note: str | None = None

    def as_dict(self) -> dict:
        return {
            "crashed": self.crashed,
            "timed_out": self.timed_out,
            "signal": self.signal,
            "signal_name": self.signal_name,
            "rip": self.rip,
            "rip_hex": None if self.rip is None else f"0x{self.rip:x}",
            "rsp": self.rsp,
            "rsp_hex": None if self.rsp is None else f"0x{self.rsp:x}",
            "stack_words": [
                {
                    "address": a,
                    "address_hex": f"0x{a:x}",
                    "value": v,
                    "value_hex": f"0x{v:x}",
                }
                for a, v in self.stack_words
            ],
            "exit_code": self.exit_code,
            "note": self.note,
        }


@dataclass
class OffsetConfirmation:
    """오프셋 확정 결과. 모든 값은 실행으로 관측된 근거를 동반한다."""

    confirmed: bool
    offset: int | None
    method: str | None  # "rip" | "stack_return_slot" | None
    pattern_length: int
    verification: str  # "verified" | "unverified"
    evidence: list[str]
    observation: CrashObservation

    def as_dict(self) -> dict:
        return {
            "confirmed": self.confirmed,
            "offset": self.offset,
            "method": self.method,
            "pattern_length": self.pattern_length,
            "verification": self.verification,
            "evidence": list(self.evidence),
            "observation": self.observation.as_dict(),
        }


def _libc() -> ctypes.CDLL:
    try:
        lib = ctypes.CDLL("libc.so.6", use_errno=True)
    except OSError as exc:  # pragma: no cover - 플랫폼 의존
        raise SandboxError(f"libc 로드 실패: {exc}") from exc
    lib.ptrace.restype = ctypes.c_long
    lib.ptrace.argtypes = [
        ctypes.c_long,
        ctypes.c_long,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    return lib


def _require_supported_platform() -> None:
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "AMD64"}:
        raise SandboxError(
            "오프셋 확정 러너는 Linux/x86-64 에서만 동작합니다: "
            f"{platform.system()}/{platform.machine()}"
        )


def _apply_child_limits(limits: SandboxLimits) -> None:
    """자식 프로세스에서 exec 직전에 호출. 실패해도 실행은 계속(best-effort)."""
    resource.setrlimit(resource.RLIMIT_CPU, (limits.cpu_seconds, limits.cpu_seconds))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    try:
        resource.setrlimit(
            resource.RLIMIT_AS,
            (limits.address_space_bytes, limits.address_space_bytes),
        )
    except (ValueError, OSError):
        pass
    try:
        resource.setrlimit(
            resource.RLIMIT_NPROC, (limits.max_processes, limits.max_processes)
        )
    except (ValueError, OSError):
        pass


def run_with_input(
    binary_path: str,
    stdin_bytes: bytes,
    *,
    limits: SandboxLimits | None = None,
) -> CrashObservation:
    """``binary_path`` 를 ``stdin_bytes`` 로 1회 실행하고 크래시를 관측한다.

    비대화형(표준입력만). 반환 시점에 자식은 반드시 종료돼 있다.
    """

    _require_supported_platform()
    limits = limits or SandboxLimits()
    limits.validate()
    if not os.path.isfile(binary_path):
        raise SandboxError(f"실행 대상 파일이 없습니다: {binary_path}")

    lib = _libc()
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:  # pragma: no cover - 자식 프로세스
        try:
            os.setsid()
            os.close(write_fd)
            os.dup2(read_fd, 0)
            os.close(read_fd)
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, 1)
            os.dup2(devnull, 2)
            _apply_child_limits(limits)
            lib.ptrace(_PTRACE_TRACEME, 0, None, None)
            os.execv(binary_path, [binary_path])
        except BaseException:
            os._exit(127)
        os._exit(127)

    # --- 부모 ---
    os.close(read_fd)
    try:
        os.write(write_fd, stdin_bytes)
    except BrokenPipeError:
        pass
    finally:
        os.close(write_fd)

    return _supervise(lib, pid, limits)


def _supervise(lib: ctypes.CDLL, pid: int, limits: SandboxLimits) -> CrashObservation:
    deadline = time.monotonic() + limits.wall_seconds

    # 1) exec 직후 SIGTRAP 정지를 소진하고 실행 재개.
    if not _wait_stop(pid, deadline):
        return _kill_group(pid, timed_out=True, note="exec 정지를 기다리다 타임아웃")
    lib.ptrace(_PTRACE_CONT, pid, None, None)

    # 2) 다음 정지 = 크래시(시그널) 또는 정상 종료.
    while True:
        if time.monotonic() > deadline:
            return _kill_group(pid, timed_out=True, note="실행 wall-clock 초과")
        try:
            waited, status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return CrashObservation(
                crashed=False,
                timed_out=False,
                signal=None,
                signal_name=None,
                rip=None,
                rsp=None,
                note="자식이 이미 회수됨",
            )
        if waited == 0:
            time.sleep(0.002)
            continue
        if os.WIFEXITED(status):
            return CrashObservation(
                crashed=False,
                timed_out=False,
                signal=None,
                signal_name=None,
                rip=None,
                rsp=None,
                exit_code=os.WEXITSTATUS(status),
                note="크래시 없이 정상 종료",
            )
        if os.WIFSIGNALED(status):
            sig = os.WTERMSIG(status)
            return CrashObservation(
                crashed=True,
                timed_out=False,
                signal=sig,
                signal_name=signal.Signals(sig).name,
                rip=None,
                rsp=None,
                note="ptrace 외부에서 시그널 종료",
            )
        if os.WIFSTOPPED(status):
            sig = os.WSTOPSIG(status)
            if sig in (signal.SIGTRAP,):
                lib.ptrace(_PTRACE_CONT, pid, None, None)
                continue
            observation = _read_crash(lib, pid, sig, limits)
            _kill_group(pid, timed_out=False, note=None)
            return observation


def _wait_stop(pid: int, deadline: float) -> bool:
    while time.monotonic() <= deadline:
        waited, status = os.waitpid(pid, os.WNOHANG)
        if waited != 0 and os.WIFSTOPPED(status):
            return True
        if waited != 0 and (os.WIFEXITED(status) or os.WIFSIGNALED(status)):
            return False
        time.sleep(0.002)
    return False


def _read_crash(
    lib: ctypes.CDLL, pid: int, sig: int, limits: SandboxLimits
) -> CrashObservation:
    regs = (ctypes.c_ulong * _REG_COUNT)()
    rc = lib.ptrace(_PTRACE_GETREGS, pid, None, ctypes.addressof(regs))
    if rc != 0:
        return CrashObservation(
            crashed=True,
            timed_out=False,
            signal=sig,
            signal_name=signal.Signals(sig).name,
            rip=None,
            rsp=None,
            note="PTRACE_GETREGS 실패",
        )
    rip = int(regs[_RIP_INDEX])
    rsp = int(regs[_RSP_INDEX])
    stack_words = _peek_stack(lib, pid, rsp, limits.stack_peek_words)
    return CrashObservation(
        crashed=True,
        timed_out=False,
        signal=sig,
        signal_name=signal.Signals(sig).name,
        rip=rip,
        rsp=rsp,
        stack_words=stack_words,
    )


def _peek_stack(
    lib: ctypes.CDLL, pid: int, rsp: int, count: int
) -> list[tuple[int, int]]:
    words: list[tuple[int, int]] = []
    for i in range(count):
        addr = rsp + i * _WORD
        ctypes.set_errno(0)
        value = lib.ptrace(_PTRACE_PEEKDATA, pid, ctypes.c_void_p(addr), None)
        if ctypes.get_errno() != 0:
            break
        words.append((addr, value & 0xFFFFFFFFFFFFFFFF))
    return words


def _kill_group(pid: int, *, timed_out: bool, note: str | None) -> CrashObservation:
    try:
        os.killpg(os.getpgid(pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass
    if note is None:
        return CrashObservation(
            crashed=True,
            timed_out=timed_out,
            signal=None,
            signal_name=None,
            rip=None,
            rsp=None,
        )
    return CrashObservation(
        crashed=False,
        timed_out=timed_out,
        signal=None,
        signal_name=None,
        rip=None,
        rsp=None,
        note=note,
    )


def confirm_return_offset(
    binary_path: str,
    *,
    pattern_length: int = 512,
    limits: SandboxLimits | None = None,
) -> OffsetConfirmation:
    """cyclic 패턴을 주입해 반환 주소까지의 오프셋을 동적으로 확정한다.

    확정 근거의 우선순위:

    1. ``RIP`` 하위 4바이트가 패턴에 존재 → ``ret`` 이 이미 패턴 값으로 점프한
       경우. 오프셋 = ``cyclic_find(rip)``.
    2. (1)이 실패하면 반환 주소 슬롯 ``[RSP]`` 의 값이 패턴에 존재하는지 확인.
       일부 커널(WSL2 등)은 non/unmapped 타깃으로의 ``ret`` 을 faulting 명령
       주소로 보고하므로, 이때 실제 반환 주소는 ``[RSP]`` 에 남아 있다.

    두 경로 모두 :func:`payload.cyclic.cyclic_find` 로 오프셋을 역산하며, 확정
    오프셋은 항상 실행으로 관측된 ``verified`` 다.
    """

    if pattern_length < 8:
        raise SandboxError("pattern_length 는 최소 8 이어야 합니다.")
    pattern = cyclic(pattern_length)
    stdin_bytes = pattern + b"\n"
    observation = run_with_input(binary_path, stdin_bytes, limits=limits)

    if not observation.crashed:
        note = observation.note or "크래시가 관측되지 않음"
        return OffsetConfirmation(
            confirmed=False,
            offset=None,
            method=None,
            pattern_length=pattern_length,
            verification="unverified",
            evidence=[f"패턴 길이 {pattern_length} 주입 → {note}"],
            observation=observation,
        )

    # 경로 1: RIP 가 패턴 값인가.
    if observation.rip is not None:
        rip_offset = cyclic_find(observation.rip & 0xFFFFFFFF)
        if rip_offset >= 0:
            return OffsetConfirmation(
                confirmed=True,
                offset=rip_offset,
                method="rip",
                pattern_length=pattern_length,
                verification="verified",
                evidence=[
                    f"{observation.signal_name} 크래시에서 RIP=0x{observation.rip:x}",
                    f"RIP 하위 4바이트가 De Bruijn 패턴 오프셋 {rip_offset} 과 일치",
                ],
                observation=observation,
            )

    # 경로 2: 반환 주소 슬롯 [RSP] 가 패턴 값인가.
    for addr, value in observation.stack_words:
        slot_offset = cyclic_find(value & 0xFFFFFFFF)
        if slot_offset >= 0:
            is_top = observation.rsp is not None and addr == observation.rsp
            return OffsetConfirmation(
                confirmed=True,
                offset=slot_offset,
                method="stack_return_slot",
                pattern_length=pattern_length,
                verification="verified",
                evidence=[
                    (
                        f"{observation.signal_name} 크래시에서 RIP=0x{observation.rip:x}"
                        if observation.rip is not None
                        else f"{observation.signal_name} 크래시"
                    ),
                    f"반환 주소 슬롯 [0x{addr:x}]"
                    + ("(=RSP)" if is_top else "")
                    + f" 값 0x{value:x} 가 패턴 오프셋 {slot_offset} 과 일치",
                ],
                observation=observation,
            )

    return OffsetConfirmation(
        confirmed=False,
        offset=None,
        method=None,
        pattern_length=pattern_length,
        verification="unverified",
        evidence=[
            f"{observation.signal_name} 크래시는 관측했으나 RIP/스택에서 "
            "패턴 일치를 찾지 못함(오프셋이 패턴 길이를 초과했을 수 있음)",
        ],
        observation=observation,
    )
