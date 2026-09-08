"""PE(Windows) 동적 실행 — wine 로 신뢰할 수 없는 PE 를 실행·관측 (Phase 7).

정적 PE 분석(:mod:`pwnable_lab.pe.parser`·:mod:`pwnable_lab.pe.analyzer`)은 실행 없이
헤더·완화·임포트를 본다. 이 모듈은 그 짝으로, ``wine`` user-space 로더로 PE 를 **실제
실행**해 stdout/stderr·종료코드·Windows 예외(크래시)를 관측한다. Windows pwnable/CTF
챌린지의 동적 트리아지 조각이다.

.. warning::
   신뢰할 수 없는 PE 를 **실행**한다. CPU rlimit·프로세스그룹 종료·wall-clock
   타임아웃만 강제하므로(RLIMIT_AS 는 wine 이 큰 주소공간을 예약해 걸 수 없다),
   프로덕션에서는 network-disabled 일회용 컨테이너 경계 안에서만 호출해야 한다
   (서비스 계층이 게이트를 강제). wine 은 자체적으로 네트워크를 막지 않는다.

wine 은 32비트 PE 실행에 별도 wine32(멀티아치)가 필요하다. 없으면 정직하게
``wine32-unavailable`` 로 보고한다(64비트는 wine64 만으로 실행).
"""

from __future__ import annotations

import os
import re
import resource
import shutil
import signal
import struct
import subprocess

from pwnable_lab.errors import SandboxError
from pwnable_lab.sandbox.runner import SandboxLimits

# 크래시로 간주하는 Windows NTSTATUS 예외 코드 → 사람이 읽는 이름.
_WIN_EXCEPTIONS = {
    0xC0000005: "ACCESS_VIOLATION",
    0xC000001D: "ILLEGAL_INSTRUCTION",
    0xC0000025: "NONCONTINUABLE_EXCEPTION",
    0xC0000094: "INTEGER_DIVIDE_BY_ZERO",
    0xC0000095: "INTEGER_OVERFLOW",
    0xC00000FD: "STACK_OVERFLOW",
    0xC0000409: "STACK_BUFFER_OVERRUN",  # /GS
    0xC0000374: "HEAP_CORRUPTION",
    0x80000003: "BREAKPOINT",
    0xC000008C: "ARRAY_BOUNDS_EXCEEDED",
}
# wine 이 처리되지 않은 예외를 stderr 로 알릴 때 쓰는 마커들.
_CRASH_MARKERS = ("unhandled exception", "unhandled page fault", "starting debugger")
# stderr 한 줄에서 fault 정보 추출:
#   "Unhandled page fault on write access to 0000...0 at address 0000...22 (thread ..)"
_FAULT_RE = re.compile(
    r"unhandled page fault on (\w+) access to ([0-9a-fA-F]+) "
    r"at address ([0-9a-fA-F]+)",
    re.IGNORECASE,
)
# stdout 에 섞이는 winedbg 덤프 시작 표식(여기서부터는 프로그램 출력이 아니다).
_DUMP_MARKER = b"Unhandled exception:"


def locate_wine() -> str | None:
    """``wine`` 실행 파일 경로(PATH). 없으면 None."""

    return shutil.which("wine")


def _pe_bits(head: bytes) -> int | None:
    """PE 헤더에서 32/64 비트를 유추한다(MZ·PE·optional magic). 아니면 None."""

    if len(head) < 0x40 or head[:2] != b"MZ":
        return None
    (e_lfanew,) = struct.unpack_from("<I", head, 0x3C)
    if e_lfanew + 0x1A > len(head) or head[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        return None
    (magic,) = struct.unpack_from("<H", head, e_lfanew + 24)
    return {0x10B: 32, 0x20B: 64}.get(magic)


def _ensure_prefix(wineprefix: str, env: dict[str, str]) -> None:
    """WINEPREFIX 를 초기화한다(이미 system.reg 있으면 건너뜀)."""

    if os.path.exists(os.path.join(wineprefix, "system.reg")):
        return
    os.makedirs(wineprefix, exist_ok=True)
    boot = shutil.which("wineboot") or "wineboot"
    subprocess.run(
        [boot, "-i"],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=180,
        check=False,
    )


def run_pe(
    binary_path: str,
    *,
    stdin_data: bytes = b"",
    argv_extra: tuple[str, ...] = (),
    wineprefix: str | None = None,
    limits: SandboxLimits | None = None,
) -> dict:
    """PE 를 wine 으로 실행하고 stdout/stderr·종료코드·크래시를 관측한다.

    ``wineprefix`` 를 주면 그 프리픽스를 재사용한다(없으면 초기화). 안 주면 바이너리
    옆에 ``.wine`` 프리픽스를 만든다. 반환은 시도여부·사용 wine·종료코드/시그널·
    타임아웃·크래시 여부(Windows 예외명)·stdout(텍스트+hex)·stderr 꼬리이다.
    """

    limits = limits or SandboxLimits()
    limits.validate()
    if not os.path.isfile(binary_path):
        raise SandboxError(f"실행 대상 파일이 없습니다: {binary_path}")

    wine = locate_wine()
    if wine is None:
        return {"attempted": False, "reason": "wine-unavailable"}

    with open(binary_path, "rb") as fh:
        head = fh.read(1024)  # DOS stub 가 e_lfanew 를 뒤로 밀 수 있어 넉넉히 읽는다
    bits = _pe_bits(head)
    if bits is None:
        return {"attempted": False, "reason": "not-pe"}
    # 32비트 PE 는 멀티아치 wine32 이 있어야 실행된다.
    if bits == 32 and shutil.which("wine32") is None and not _has_wine32(wine):
        return {"attempted": False, "reason": "wine32-unavailable", "bits": 32}

    prefix = wineprefix or (binary_path + ".wine")
    env = dict(os.environ)
    env.update(
        WINEPREFIX=prefix,
        WINEDEBUG="-all",
        WINEDLLOVERRIDES="mscoree,mshtml=",  # gecko/mono 설치 프롬프트 차단
        DISPLAY="",  # GUI 없음(headless)
    )
    _ensure_prefix(prefix, env)

    def _preexec() -> None:  # pragma: no cover - 자식 프로세스
        os.setsid()
        cpu = limits.cpu_seconds
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        # RLIMIT_AS 미설정: wine 은 게스트용 큰 주소공간을 예약 → AS 상한이 wine 을 죽인다.

    argv = [wine, binary_path, *argv_extra]
    proc = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        preexec_fn=_preexec,
        env=env,
    )
    timed_out = False
    try:
        out, err = proc.communicate(input=stdin_data, timeout=limits.wall_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()
        out, err = proc.communicate()

    out = out or b""
    err = err or b""
    rc = proc.returncode
    exit_code = rc if rc is not None and rc >= 0 else None
    term_signal = -rc if rc is not None and rc < 0 else None

    err_text = err.decode("utf-8", "replace")
    # 크래시 시 wine 은 winedbg 덤프를 stdout 에 붙인다 → 프로그램 실제 출력만 남긴다.
    program_out = out.split(_DUMP_MARKER, 1)[0]
    cap = limits.capture_stdout_bytes
    truncated = len(program_out) > cap
    program_out = program_out[:cap]

    crash = _detect_crash(exit_code, err_text)

    return {
        "attempted": True,
        "wine": os.path.basename(wine),
        "bits": bits,
        "timed_out": timed_out,
        "exit_code": exit_code,
        "signal": term_signal,
        "signal_name": (signal.Signals(term_signal).name if term_signal else None),
        "crashed": crash is not None,
        "crash": crash,
        "truncated": truncated,
        "stdout": program_out.decode("utf-8", "replace"),
        "stdout_hex": program_out.hex(),
        "stderr_tail": err_text[-4000:],
    }


def _has_wine32(wine: str) -> bool:
    """wine 이 32비트 PE 를 실행할 수 있는지(멀티아치/32비트 빌드) 대략 판별."""

    # wine64 전용 설치는 32비트를 못 돌린다. 보수적으로: wine --version 이 wine32 부재를
    # 경고하지 않으면 가능으로 본다.
    try:
        res = subprocess.run(
            [wine, "--version"], capture_output=True, text=True, timeout=15
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return "wine32 is missing" not in (res.stdout + res.stderr).lower()


def _detect_crash(exit_code: int | None, err_text: str) -> dict | None:
    """종료코드/stderr 로 Windows 예외(크래시)를 판별·구조화한다(없으면 None).

    반환(크래시 시): reason(예외명)·access(read/write/execute)·fault_address(접근한
    잘못된 주소)·instruction_pointer(faulting 명령 주소). page fault 가 아니면
    reason 만 채운다.
    """

    lowered = err_text.lower()
    marker_hit = any(m in lowered for m in _CRASH_MARKERS)

    fault = _FAULT_RE.search(err_text)
    if fault:
        access, target, rip = fault.group(1), fault.group(2), fault.group(3)
        return {
            "reason": "ACCESS_VIOLATION",
            "access": access.lower(),
            "fault_address": f"0x{int(target, 16):x}",
            "instruction_pointer": f"0x{int(rip, 16):x}",
        }
    if marker_hit:
        for code, name in _WIN_EXCEPTIONS.items():
            if f"{code:08x}" in lowered:
                return {"reason": name}
        return {"reason": "UNHANDLED_EXCEPTION"}
    if exit_code is not None and exit_code in _WIN_EXCEPTIONS:
        # wine 이 NTSTATUS 를 종료코드로 전달한 경우.
        return {"reason": _WIN_EXCEPTIONS[exit_code]}
    return None


__all__ = ["locate_wine", "run_pe"]
