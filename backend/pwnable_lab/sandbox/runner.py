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
import select
import signal
import time
import tty
from collections.abc import Callable
from dataclasses import dataclass, field

from pwnable_lab.errors import SandboxError
from pwnable_lab.payload.cyclic import cyclic, cyclic_find

# --- ptrace 상수 (Linux/x86-64) ---
_PTRACE_TRACEME = 0
_PTRACE_PEEKDATA = 2
_PTRACE_CONT = 7
_PTRACE_KILL = 8
_PTRACE_GETREGS = 12

# personality(2) ADDR_NO_RANDOMIZE: 자식의 PIE/스택 로드 base 를 결정적으로 고정.
_ADDR_NO_RANDOMIZE = 0x0040000

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
    # 셸 spawn 경로(fork 필수)에서 현재 프로세스 수 위로 허용할 여유분. 이 값이
    # in-process fork-bomb 의 상한이 된다(컨테이너에서는 --pids-limit 가 우선).
    shell_process_headroom: int = 64
    stack_peek_words: int = 8
    capture_stdout_bytes: int = 4096  # stdout 캡처 상한(payload 검증용)

    def validate(self) -> None:
        if self.wall_seconds <= 0 or self.cpu_seconds <= 0:
            raise SandboxError("시간 상한은 양수여야 합니다.")
        if self.stack_peek_words < 1:
            raise SandboxError("stack_peek_words 는 1 이상이어야 합니다.")
        if self.capture_stdout_bytes < 0:
            raise SandboxError("capture_stdout_bytes 는 0 이상이어야 합니다.")


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
    stdout: bytes = b""  # capture_stdout=True 일 때만 채워짐

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
            "stdout": self.stdout.decode("utf-8", "replace"),
            # 원시 바이트(주소 leak 등 비텍스트 출력이 JSON/컨테이너 경계를
            # 넘어도 손실되지 않도록 hex 로도 보존).
            "stdout_hex": self.stdout.hex(),
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


def _disable_aslr() -> None:
    """personality(ADDR_NO_RANDOMIZE) 로 자식의 ASLR 을 끈다(best-effort).

    PIE 자동 익스는 로드 base 를 *로컬 관측*(:func:`resolve_pie_base`)으로 확정한
    뒤 그 base 로 payload 를 rebase 한다. 관측 실행과 검증 실행의 base 가 반드시
    같아야 하므로 양쪽 모두 ASLR 을 꺼 base 를 결정적으로 만든다. 이는 원격 ASLR
    우회가 아니라 **로컬 익스 가능성 증명**이다(docs/AUTO_EXPLOIT_SANDBOX.md 참조).
    """
    try:
        lib = ctypes.CDLL("libc.so.6", use_errno=True)
        lib.personality.restype = ctypes.c_int
        lib.personality.argtypes = [ctypes.c_ulong]
        lib.personality(_ADDR_NO_RANDOMIZE)
    except OSError:  # pragma: no cover - 플랫폼 의존
        pass


def _require_supported_platform() -> None:
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "AMD64"}:
        raise SandboxError(
            "오프셋 확정 러너는 Linux/x86-64 에서만 동작합니다: "
            f"{platform.system()}/{platform.machine()}"
        )


def _estimate_task_count() -> int:
    """현재 시스템의 대략적인 **태스크(스레드 포함) 수**. 실패 시 0.

    ``RLIMIT_NPROC`` 은 프로세스가 아니라 실사용자의 태스크(스레드 포함)를 세므로,
    셸 spawn 을 허용하는 상한을 잡으려면 프로세스가 아니라 태스크를 기준으로
    추정해야 한다(멀티스레드 프로세스가 많으면 태스크 수 ≫ 프로세스 수).
    """
    total = 0
    try:
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            try:
                total += len(os.listdir(f"/proc/{entry}/task"))
            except OSError:
                total += 1
    except OSError:  # pragma: no cover - 플랫폼 의존
        return 0
    return total


def _apply_child_limits(
    limits: SandboxLimits, *, process_headroom: int | None = None
) -> None:
    """자식 프로세스에서 exec 직전에 호출. 실패해도 실행은 계속(best-effort).

    ``RLIMIT_NPROC`` 은 **실사용자 전체(호스트 공유)** 프로세스를 세므로 절대값으로
    걸면 바쁜 호스트에서 fork 를 막거나(예: 셸 spawn) 반대로 bomb 을 못 막는다.

    * ``process_headroom is None`` (기본): 포크가 필요 없는 경로 — 절대 상한
      ``limits.max_processes``. (대상이 fork 하지 않으므로 현재 사용량보다 낮아도
      실행에는 문제없고, 새 fork 만 막힌다.)
    * ``process_headroom`` 지정: 셸을 spawn 해야 하는 경로(fork 필수) — **현재
      프로세스 수 + headroom** 으로 상한을 잡아 셸 fork 는 허용하되 fork-bomb 은
      바운드한다(컨테이너 ``--pids-limit`` 위의 in-process 방어선).
    """
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
    if process_headroom is None:
        nproc = limits.max_processes
    else:
        nproc = _estimate_task_count() + max(1, process_headroom)
    try:
        resource.setrlimit(resource.RLIMIT_NPROC, (nproc, nproc))
    except (ValueError, OSError):
        pass


def run_with_input(
    binary_path: str,
    stdin_bytes: bytes,
    *,
    limits: SandboxLimits | None = None,
    capture_stdout: bool = False,
    disable_aslr: bool = False,
) -> CrashObservation:
    """``binary_path`` 를 ``stdin_bytes`` 로 1회 실행하고 크래시를 관측한다.

    비대화형(표준입력만). 반환 시점에 자식은 반드시 종료돼 있다.
    ``capture_stdout=True`` 면 자식 stdout 을 파이프로 받아
    ``CrashObservation.stdout`` 에 ``limits.capture_stdout_bytes`` 까지 담는다.
    (stderr 는 항상 버린다. 대상의 stdout 이 full-buffered 라 크래시 시점에
    flush 되지 않았을 수 있음에 유의 — 성공 판정을 stdout 에만 의존하지 말 것.)
    ``disable_aslr=True`` 면 자식의 ASLR 을 꺼 로드 base 를 결정적으로 만든다
    (PIE 자동 익스에서 관측 base 와 검증 base 를 일치시키기 위함).
    """

    _require_supported_platform()
    limits = limits or SandboxLimits()
    limits.validate()
    if not os.path.isfile(binary_path):
        raise SandboxError(f"실행 대상 파일이 없습니다: {binary_path}")

    lib = _libc()
    read_fd, write_fd = os.pipe()
    capture: tuple[int, int] | None = os.pipe() if capture_stdout else None
    pid = os.fork()
    if pid == 0:  # pragma: no cover - 자식 프로세스
        try:
            os.setsid()
            os.close(write_fd)
            os.dup2(read_fd, 0)
            os.close(read_fd)
            devnull = os.open(os.devnull, os.O_WRONLY)
            if capture is not None:
                child_read, child_write = capture
                os.close(child_read)
                os.dup2(child_write, 1)
                os.close(child_write)
            else:
                os.dup2(devnull, 1)
            os.dup2(devnull, 2)
            if disable_aslr:
                _disable_aslr()
            _apply_child_limits(limits)
            lib.ptrace(_PTRACE_TRACEME, 0, None, None)
            os.execv(binary_path, [binary_path])
        except BaseException:
            os._exit(127)
        os._exit(127)

    # --- 부모 ---
    os.close(read_fd)
    out_read: int | None = None
    if capture is not None:
        out_read, out_write = capture
        os.close(out_write)
        os.set_blocking(out_read, False)
    try:
        os.write(write_fd, stdin_bytes)
    except BrokenPipeError:
        pass
    finally:
        os.close(write_fd)

    try:
        return _supervise(lib, pid, limits, out_fd=out_read)
    finally:
        if out_read is not None:
            os.close(out_read)


def _supervise(
    lib: ctypes.CDLL,
    pid: int,
    limits: SandboxLimits,
    *,
    out_fd: int | None = None,
) -> CrashObservation:
    deadline = time.monotonic() + limits.wall_seconds
    stdout_buf = bytearray()

    def drain() -> None:
        if out_fd is None:
            return
        cap = limits.capture_stdout_bytes
        while len(stdout_buf) < cap:
            try:
                chunk = os.read(out_fd, min(4096, cap - len(stdout_buf)))
            except (BlockingIOError, OSError):
                break
            if not chunk:
                break
            stdout_buf.extend(chunk)

    def finish(observation: CrashObservation) -> CrashObservation:
        drain()
        observation.stdout = bytes(stdout_buf)
        return observation

    # 1) exec 직후 SIGTRAP 정지를 소진하고 실행 재개.
    if not _wait_stop(pid, deadline):
        return finish(
            _kill_group(pid, timed_out=True, note="exec 정지를 기다리다 타임아웃")
        )
    lib.ptrace(_PTRACE_CONT, pid, None, None)

    # 2) 다음 정지 = 크래시(시그널) 또는 정상 종료.
    while True:
        drain()
        if time.monotonic() > deadline:
            return finish(_kill_group(pid, timed_out=True, note="실행 wall-clock 초과"))
        try:
            waited, status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return finish(
                CrashObservation(
                    crashed=False,
                    timed_out=False,
                    signal=None,
                    signal_name=None,
                    rip=None,
                    rsp=None,
                    note="자식이 이미 회수됨",
                )
            )
        if waited == 0:
            time.sleep(0.002)
            continue
        if os.WIFEXITED(status):
            return finish(
                CrashObservation(
                    crashed=False,
                    timed_out=False,
                    signal=None,
                    signal_name=None,
                    rip=None,
                    rsp=None,
                    exit_code=os.WEXITSTATUS(status),
                    note="크래시 없이 정상 종료",
                )
            )
        if os.WIFSIGNALED(status):
            sig = os.WTERMSIG(status)
            return finish(
                CrashObservation(
                    crashed=True,
                    timed_out=False,
                    signal=sig,
                    signal_name=signal.Signals(sig).name,
                    rip=None,
                    rsp=None,
                    note="ptrace 외부에서 시그널 종료",
                )
            )
        if os.WIFSTOPPED(status):
            sig = os.WSTOPSIG(status)
            if sig in (signal.SIGTRAP,):
                lib.ptrace(_PTRACE_CONT, pid, None, None)
                continue
            observation = _read_crash(lib, pid, sig, limits)
            _kill_group(pid, timed_out=False, note=None)
            return finish(observation)


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


# --- payload 검증 (제어 흐름 탈취 확인) -------------------------------------


@dataclass
class ExploitVerification:
    """구성한 payload 를 실제로 주입한 결과. 성공 판정과 근거를 동반한다."""

    succeeded: bool
    reason: str  # "marker-match" | "marker-missing" | "control-transfer" | "crashed"
    matched_markers: list[str]
    payload_length: int
    observation: CrashObservation

    def as_dict(self) -> dict:
        return {
            "succeeded": self.succeeded,
            "reason": self.reason,
            "matched_markers": list(self.matched_markers),
            "payload_length": self.payload_length,
            "observation": self.observation.as_dict(),
        }


def verify_payload(
    binary_path: str,
    payload: bytes,
    *,
    success_markers: list[str] | tuple[str, ...] = (),
    limits: SandboxLimits | None = None,
    append_newline: bool = True,
    disable_aslr: bool = False,
) -> ExploitVerification:
    """``payload`` 를 stdin 으로 주입해 익스가 실제로 먹히는지 관측한다.

    성공 판정:

    * ``success_markers`` 가 주어지면 stdout 에 그 문자열 중 하나라도 나타나면
      성공(가장 강한 증거 — 예: win 함수가 출력하는 플래그/메시지).
    * 마커가 없으면 **크래시 없이 제어가 유효 타깃으로 이전**됐는지로 판정한다
      (오프셋/주소가 맞으면 대상 함수가 실행돼 SIGSEGV 없이 끝난다). stdout 은
      full-buffered 라 크래시 시 유실될 수 있으므로 마커 단독에 의존하지 않는다.
    """

    stdin_bytes = payload + b"\n" if append_newline else payload
    observation = run_with_input(
        binary_path,
        stdin_bytes,
        limits=limits,
        capture_stdout=True,
        disable_aslr=disable_aslr,
    )
    text = observation.stdout.decode("utf-8", "replace")
    matched = [m for m in success_markers if m and m in text]

    if success_markers:
        succeeded = bool(matched)
        reason = "marker-match" if succeeded else "marker-missing"
    else:
        succeeded = not observation.crashed
        reason = "control-transfer" if succeeded else "crashed"

    return ExploitVerification(
        succeeded=succeeded,
        reason=reason,
        matched_markers=matched,
        payload_length=len(payload),
        observation=observation,
    )


# --- 멀티스테이지(leak → 2단계 payload) 러너 ------------------------------


def run_two_stage(
    binary_path: str,
    make_second: Callable[[bytes], bytes],
    *,
    prelude: bytes = b"",
    limits: SandboxLimits | None = None,
) -> tuple[CrashObservation, bytes]:
    """대상이 유출한 값을 읽어 2단계 payload 를 만들어 되쏘는 상호작용 러너.

    흐름: exec → (선택) ``prelude`` 전송 → stdout 첫 줄(유출) 수신 →
    ``make_second(first_line_bytes)`` 로 2단계 payload 구성 → 전송 → 종료까지 관측.
    leak→ret2libc 처럼 "출력을 읽고 그 값으로 다음 입력을 만드는" 익스의 기반이다.

    반환: ``(관측결과, 유출된_첫_줄_bytes)``. 첫 줄을 받기 전에 종료/타임아웃하면
    2단계는 보내지 않으며 유출 bytes 는 비어 있을 수 있다(대상 stdout 버퍼링 등).

    .. note::
       대상 stdout 이 full-buffered 면 유출이 종료 전까지 flush 되지 않아 이 방식이
       동작하지 않는다(CTF 바이너리는 보통 ``setvbuf`` 로 무버퍼라 동작). stderr 는
       버린다.
    """

    _require_supported_platform()
    limits = limits or SandboxLimits()
    limits.validate()
    if not os.path.isfile(binary_path):
        raise SandboxError(f"실행 대상 파일이 없습니다: {binary_path}")

    lib = _libc()
    in_read, in_write = os.pipe()
    out_read, out_write = os.pipe()
    pid = os.fork()
    if pid == 0:  # pragma: no cover - 자식 프로세스
        try:
            os.setsid()
            os.close(in_write)
            os.close(out_read)
            os.dup2(in_read, 0)
            os.close(in_read)
            os.dup2(out_write, 1)
            os.close(out_write)
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, 2)
            _apply_child_limits(limits)
            lib.ptrace(_PTRACE_TRACEME, 0, None, None)
            os.execv(binary_path, [binary_path])
        except BaseException:
            os._exit(127)
        os._exit(127)

    os.close(in_read)
    os.close(out_write)
    os.set_blocking(out_read, False)
    if prelude:
        try:
            os.write(in_write, prelude)
        except BrokenPipeError:
            pass
    try:
        return _supervise_two_stage(lib, pid, limits, in_write, out_read, make_second)
    finally:
        for fd in (in_write, out_read):
            try:
                os.close(fd)
            except OSError:
                pass


def _supervise_two_stage(
    lib: ctypes.CDLL,
    pid: int,
    limits: SandboxLimits,
    in_write: int,
    out_fd: int,
    make_second: Callable[[bytes], bytes],
) -> tuple[CrashObservation, bytes]:
    deadline = time.monotonic() + limits.wall_seconds
    stdout_buf = bytearray()
    first_line: bytes | None = None
    stage2_sent = False

    def drain() -> None:
        cap = limits.capture_stdout_bytes
        while len(stdout_buf) < cap:
            try:
                chunk = os.read(out_fd, min(4096, cap - len(stdout_buf)))
            except (BlockingIOError, OSError):
                break
            if not chunk:
                break
            stdout_buf.extend(chunk)

    def maybe_stage2() -> None:
        nonlocal first_line, stage2_sent
        if stage2_sent or b"\n" not in stdout_buf:
            return
        first_line = bytes(stdout_buf).split(b"\n", 1)[0]
        stage2_sent = True
        try:
            os.write(in_write, make_second(first_line))
        except (BrokenPipeError, OSError):
            pass
        try:
            os.close(in_write)
        except OSError:
            pass

    def finish(observation: CrashObservation) -> tuple[CrashObservation, bytes]:
        drain()
        maybe_stage2()
        drain()
        observation.stdout = bytes(stdout_buf)
        return observation, (first_line or b"")

    if not _wait_stop(pid, deadline):
        return finish(
            _kill_group(pid, timed_out=True, note="exec 정지를 기다리다 타임아웃")
        )
    lib.ptrace(_PTRACE_CONT, pid, None, None)

    while True:
        drain()
        maybe_stage2()
        if time.monotonic() > deadline:
            return finish(_kill_group(pid, timed_out=True, note="실행 wall-clock 초과"))
        try:
            waited, status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return finish(
                CrashObservation(
                    crashed=False,
                    timed_out=False,
                    signal=None,
                    signal_name=None,
                    rip=None,
                    rsp=None,
                    note="자식이 이미 회수됨",
                )
            )
        if waited == 0:
            time.sleep(0.002)
            continue
        if os.WIFEXITED(status):
            return finish(
                CrashObservation(
                    crashed=False,
                    timed_out=False,
                    signal=None,
                    signal_name=None,
                    rip=None,
                    rsp=None,
                    exit_code=os.WEXITSTATUS(status),
                    note="크래시 없이 정상 종료",
                )
            )
        if os.WIFSIGNALED(status):
            sig = os.WTERMSIG(status)
            return finish(
                CrashObservation(
                    crashed=True,
                    timed_out=False,
                    signal=sig,
                    signal_name=signal.Signals(sig).name,
                    rip=None,
                    rsp=None,
                    note="ptrace 외부에서 시그널 종료",
                )
            )
        if os.WIFSTOPPED(status):
            sig = os.WSTOPSIG(status)
            if sig == signal.SIGTRAP:
                lib.ptrace(_PTRACE_CONT, pid, None, None)
                continue
            observation = _read_crash(lib, pid, sig, limits)
            _kill_group(pid, timed_out=False, note=None)
            return finish(observation)


# --- PTY 셸 증명 (ret2system/ret2libc 가 실제 셸을 띄우는지) -----------------


@dataclass
class ShellProof:
    """spawn 된 셸에서 명령이 실제로 실행됐는지에 대한 증명."""

    shell_spawned: bool
    marker: str
    command: str
    output: bytes

    def as_dict(self) -> dict:
        return {
            "shell_spawned": self.shell_spawned,
            "marker": self.marker,
            "command": self.command,
            "output": self.output.decode("utf-8", "replace"),
            "output_hex": self.output.hex(),
        }


def verify_shell(
    binary_path: str,
    payload: bytes,
    *,
    marker: str,
    command: str | None = None,
    limits: SandboxLimits | None = None,
    disable_aslr: bool = False,
) -> ShellProof:
    """PTY 로 payload 를 주입해 **셸이 실제로 명령을 실행**하는지 증명한다.

    ret2system/ret2libc payload 가 ``system("/bin/sh")`` 로 셸을 띄우면, 그 셸은
    PTY(tty)에 붙어 대화형으로 stdin 을 읽는다. 우리가 ``echo <marker>`` 를 보내면
    셸이 실행해 marker 를 출력하므로, marker 관측 = 셸 획득 증명이다(파이프의 stdio
    버퍼링 문제를 tty 라인 규율이 우회한다).

    tty 라인 규율이 payload 의 제어바이트를 해석하지 않도록 raw 모드로 둔다.
    """

    _require_supported_platform()
    limits = limits or SandboxLimits()
    limits.validate()
    if not os.path.isfile(binary_path):
        raise SandboxError(f"실행 대상 파일이 없습니다: {binary_path}")

    cmd = command or f"echo {marker}"
    master, slave = os.openpty()
    tty.setraw(slave)  # payload 바이트 보존(특수문자 해석 방지)

    pid = os.fork()
    if pid == 0:  # pragma: no cover - 자식 프로세스
        try:
            os.setsid()
            os.dup2(slave, 0)
            os.dup2(slave, 1)
            os.dup2(slave, 2)
            os.close(master)
            os.close(slave)
            if disable_aslr:
                _disable_aslr()
            # 셸 spawn 은 fork 가 필수라 NPROC 상한을 걸지 않는다(위 함수 주석 참조).
            _apply_child_limits(limits, process_headroom=limits.shell_process_headroom)
            os.execv(binary_path, [binary_path])
        except BaseException:
            os._exit(127)
        os._exit(127)

    os.close(slave)
    marker_bytes = marker.encode()
    output = bytearray()
    try:
        os.write(master, payload + b"\n")
        time.sleep(0.15)
        os.write(master, cmd.encode() + b"\n")
    except OSError:
        pass

    deadline = time.monotonic() + limits.wall_seconds
    cap = limits.capture_stdout_bytes
    while time.monotonic() < deadline and len(output) < cap:
        ready, _, _ = select.select([master], [], [], 0.1)
        if not ready:
            continue
        try:
            chunk = os.read(master, 4096)
        except OSError:
            break
        if not chunk:
            break
        output.extend(chunk)
        if marker_bytes in output:
            break

    try:
        os.close(master)
    except OSError:
        pass
    _kill_group(pid, timed_out=False, note=None)

    return ShellProof(
        shell_spawned=marker_bytes in bytes(output),
        marker=marker,
        command=cmd,
        output=bytes(output[:cap]),
    )


def run_two_stage_shell(
    binary_path: str,
    make_second: Callable[[bytes], bytes],
    *,
    marker: str,
    prelude: bytes = b"",
    command: str | None = None,
    limits: SandboxLimits | None = None,
    disable_aslr: bool = False,
) -> tuple[ShellProof, bytes]:
    """PTY 로 2단계(leak→stage2)를 몰고, spawn 된 셸에 명령을 흘려 증명한다.

    ret2libc 처럼 "유출을 읽어 2단계를 만들고, 그 2단계가 ``system("/bin/sh")`` 로
    셸을 띄우는" 흐름을 PTY 위에서 수행한다. tty 라인 규율 덕에 대상 stdout 이
    라인버퍼(무버퍼 setvbuf 불필요)라 유출이 즉시 flush 되고, 셸도 대화형으로
    ``echo <marker>`` 를 읽어 실행한다. 반환: ``(ShellProof, 유출된_첫_줄_bytes)``.

    ``disable_aslr=True`` 면 자식의 ASLR 을 끈다. 포맷스트링 in-band leak 처럼
    유출값으로 base 를 계산하는 익스는 ASLR 이 켜져 있어도 성립하지만(그게 핵심),
    셸 증명의 재현성을 위해 끌 수 있다.
    """

    _require_supported_platform()
    limits = limits or SandboxLimits()
    limits.validate()
    if not os.path.isfile(binary_path):
        raise SandboxError(f"실행 대상 파일이 없습니다: {binary_path}")

    cmd = command or f"echo {marker}"
    marker_bytes = marker.encode()
    master, slave = os.openpty()
    tty.setraw(slave)

    pid = os.fork()
    if pid == 0:  # pragma: no cover - 자식 프로세스
        try:
            os.setsid()
            os.dup2(slave, 0)
            os.dup2(slave, 1)
            os.dup2(slave, 2)
            os.close(master)
            os.close(slave)
            if disable_aslr:
                _disable_aslr()
            _apply_child_limits(limits, process_headroom=limits.shell_process_headroom)
            os.execv(binary_path, [binary_path])
        except BaseException:
            os._exit(127)
        os._exit(127)

    os.close(slave)
    output = bytearray()
    first_line: bytes | None = None
    stage2_sent = False
    command_sent = False
    cap = limits.capture_stdout_bytes
    deadline = time.monotonic() + limits.wall_seconds

    try:
        os.write(master, prelude + b"\n")
    except OSError:
        pass

    while time.monotonic() < deadline and len(output) < cap:
        ready, _, _ = select.select([master], [], [], 0.1)
        if ready:
            try:
                chunk = os.read(master, 4096)
            except OSError:
                break
            if not chunk:
                break
            output.extend(chunk)
            if marker_bytes in output:
                break
        # 유출 첫 줄을 받으면 2단계를 만들어 보낸다.
        if not stage2_sent and b"\n" in output:
            first_line = bytes(output).split(b"\n", 1)[0]
            stage2_sent = True
            try:
                os.write(master, make_second(first_line) + b"\n")
            except OSError:
                pass
        # 2단계를 보낸 뒤 셸에 명령을 흘린다(짧은 대기 후 1회).
        elif stage2_sent and not command_sent:
            command_sent = True
            time.sleep(0.15)
            try:
                os.write(master, cmd.encode() + b"\n")
            except OSError:
                pass

    try:
        os.close(master)
    except OSError:
        pass
    _kill_group(pid, timed_out=False, note=None)

    proof = ShellProof(
        shell_spawned=marker_bytes in bytes(output),
        marker=marker,
        command=cmd,
        output=bytes(output[:cap]),
    )
    return proof, (first_line or b"")


# --- PIE 로드 base 로컬 관측 ------------------------------------------------


@dataclass
class PieBaseResolution:
    """PIE 바이너리의 런타임 로드 base 를 로컬에서 관측한 결과.

    ASLR 을 끈 자식을 exec 직후(exec-stop) 정지시키고 ``/proc/<pid>/maps`` 에서
    대상 바이너리의 최저 매핑 주소를 base 로 읽는다. base 는 결정적(ASLR-off)이라
    같은 조건의 검증 실행과 정확히 일치한다. 이는 원격 ASLR 우회가 아니라 **로컬
    익스 가능성 증명**을 위한 관측 오라클이다.
    """

    confirmed: bool
    base: int | None
    note: str | None = None

    def as_dict(self) -> dict:
        return {
            "confirmed": self.confirmed,
            "base": self.base,
            "base_hex": None if self.base is None else f"0x{self.base:x}",
            "note": self.note,
        }


def _read_pie_base(pid: int, binary_path: str) -> int | None:
    """``/proc/<pid>/maps`` 에서 대상 바이너리의 최저 매핑 주소(로드 base)를 읽는다.

    표준 PIE 는 첫 LOAD 세그먼트의 vaddr 이 0 이므로 최저 매핑 시작 = 로드 base 다
    (ELF 심볼 st_value 에 그대로 더하면 런타임 주소).
    """
    target = os.path.realpath(binary_path)
    base: int | None = None
    try:
        with open(f"/proc/{pid}/maps", encoding="utf-8") as maps:
            for line in maps:
                parts = line.split()
                if len(parts) < 6:
                    continue
                path = parts[5]
                if path != target and os.path.realpath(path) != target:
                    continue
                start = int(parts[0].split("-", 1)[0], 16)
                base = start if base is None else min(base, start)
    except OSError:
        return None
    return base


def resolve_pie_base(
    binary_path: str, *, limits: SandboxLimits | None = None
) -> PieBaseResolution:
    """ASLR 을 끈 자식을 exec-stop 에서 정지시켜 PIE 로드 base 를 관측한다.

    자식은 ``PTRACE_TRACEME`` 후 execv 하고, 첫 SIGTRAP(exec-stop) 에서 새 이미지가
    이미 매핑돼 있어 ``/proc/<pid>/maps`` 로 base 를 회수할 수 있다. 관측 후 즉시
    프로세스그룹을 종료한다. stdin/stdout/stderr 는 모두 /dev/null.
    """

    _require_supported_platform()
    limits = limits or SandboxLimits()
    limits.validate()
    if not os.path.isfile(binary_path):
        raise SandboxError(f"실행 대상 파일이 없습니다: {binary_path}")

    lib = _libc()
    pid = os.fork()
    if pid == 0:  # pragma: no cover - 자식 프로세스
        try:
            os.setsid()
            devnull_r = os.open(os.devnull, os.O_RDONLY)
            devnull_w = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull_r, 0)
            os.dup2(devnull_w, 1)
            os.dup2(devnull_w, 2)
            _disable_aslr()
            _apply_child_limits(limits)
            lib.ptrace(_PTRACE_TRACEME, 0, None, None)
            os.execv(binary_path, [binary_path])
        except BaseException:
            os._exit(127)
        os._exit(127)

    deadline = time.monotonic() + limits.wall_seconds
    try:
        if not _wait_stop(pid, deadline):
            return PieBaseResolution(
                confirmed=False, base=None, note="exec 정지 대기 타임아웃/조기 종료"
            )
        base = _read_pie_base(pid, binary_path)
        if base is None:
            return PieBaseResolution(
                confirmed=False, base=None, note="maps 에서 로드 base 를 찾지 못함"
            )
        return PieBaseResolution(confirmed=True, base=base)
    finally:
        _kill_group(pid, timed_out=False, note=None)
