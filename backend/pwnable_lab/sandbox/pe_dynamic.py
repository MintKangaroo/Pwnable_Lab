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
# page fault 전용: access 종류·대상 주소·faulting 명령 주소까지 추출.
#   "Unhandled page fault on write access to 0000...0 at address 0000...22 (thread ..)"
_FAULT_RE = re.compile(
    r"unhandled page fault on (\w+) access to ([0-9a-fA-F]+) "
    r"at address ([0-9a-fA-F]+)",
    re.IGNORECASE,
)
# 일반 예외: "Unhandled <type> at address <hex>" (illegal instruction/stack overflow 등).
_GENERIC_FAULT_RE = re.compile(
    r"unhandled (.+?) at address ([0-9a-fA-F]+)", re.IGNORECASE
)
# wine 예외 문구 → NTSTATUS 이름.
_PHRASE_TO_REASON = {
    "illegal instruction": "ILLEGAL_INSTRUCTION",
    "page fault": "ACCESS_VIOLATION",
    "stack overflow": "STACK_OVERFLOW",
    "divide by zero": "INTEGER_DIVIDE_BY_ZERO",
    "privileged instruction": "PRIVILEGED_INSTRUCTION",
    "breakpoint": "BREAKPOINT",
}
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
        except (ProcessLookupError, PermissionError):  # pragma: no cover - 경쟁 방어
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
    # 일반 예외(illegal instruction/stack overflow 등): 문구 + faulting 주소.
    generic = _GENERIC_FAULT_RE.search(err_text)
    if generic:
        phrase, rip = generic.group(1).strip().lower(), generic.group(2)
        reason = next(
            (r for p, r in _PHRASE_TO_REASON.items() if p in phrase),
            "UNHANDLED_EXCEPTION",
        )
        return {"reason": reason, "instruction_pointer": f"0x{int(rip, 16):x}"}
    if marker_hit:
        for code, name in _WIN_EXCEPTIONS.items():
            if f"{code:08x}" in lowered:
                return {"reason": name}
        return {"reason": "UNHANDLED_EXCEPTION"}
    if exit_code is not None and exit_code in _WIN_EXCEPTIONS:
        # wine 이 NTSTATUS 를 종료코드로 전달한 경우.
        return {"reason": _WIN_EXCEPTIONS[exit_code]}
    return None


def _cyclic(length: int) -> bytes:
    """de Bruijn 류 비반복 패턴(4바이트 주기). 반환주소 오염 시 크래시 유발률↑.

    pwntools 의존 없이 'aaaa','baaa',... 4글자 그룹을 이어 붙인다(모든 A 같은 단일
    바이트 패턴은 /GS 쿠키 경로에서 크래시하지 않을 수 있어 회피).
    """

    alphabet = b"abcdefghijklmnopqrstuvwxyz"
    out = bytearray()
    for a in alphabet:
        for b in alphabet:
            for c in alphabet:
                for d in alphabet:
                    out += bytes((a, b, c, d))
                    if len(out) >= length:
                        return bytes(out[:length])
    return bytes(out[:length])  # pragma: no cover - 알파벳 소진(비현실적 길이)


# PE 크래시 트리아지에 쓰는 기본 probe 배터리(입력 클래스별 대표).
_DEFAULT_PROBES: tuple[tuple[str, bytes], ...] = (
    ("baseline", b""),
    ("overflow", _cyclic(300)),
    ("format", b"%p." * 32 + b"%n" * 4),
    ("negative", b"-1\n-2147483648\n"),
)


def pe_crash_triage(
    binary_path: str,
    *,
    probes: tuple[tuple[str, bytes], ...] = _DEFAULT_PROBES,
    wineprefix: str | None = None,
    limits: SandboxLimits | None = None,
) -> dict:
    """PE 에 입력 probe 배터리를 주입해 크래시를 분류한다(동적 취약점 트리아지).

    각 probe(overflow/format/negative 등)를 stdin 으로 넣고 실행해 크래시 여부·예외
    종류·faulting 주소를 모은다. baseline(빈 입력)이 정상이고 특정 probe 에서만
    크래시하면 그 입력 클래스가 취약 신호다. wine 부재 시 attempted=False.
    """

    limits = limits or SandboxLimits()
    results: list[dict] = []
    attempted = False
    for name, payload in probes:
        run = run_pe(
            binary_path,
            stdin_data=payload,
            wineprefix=wineprefix,
            limits=limits,
        )
        if not run.get("attempted"):
            return {"attempted": False, "reason": run.get("reason")}
        attempted = True
        results.append(
            {
                "probe": name,
                "input_len": len(payload),
                "crashed": run["crashed"],
                "crash": run["crash"],
                "exit_code": run["exit_code"],
                "timed_out": run["timed_out"],
            }
        )

    baseline = next((r for r in results if r["probe"] == "baseline"), None)
    baseline_ok = bool(baseline and not baseline["crashed"])
    crashing = [r["probe"] for r in results if r["crashed"]]
    reasons = {r["crash"]["reason"] for r in results if r["crash"]}
    return {
        "attempted": attempted,
        "baseline_ok": baseline_ok,
        "crashing_probes": crashing,
        "crash_reasons": sorted(reasons),
        # baseline 은 멀쩡한데 overflow 만 죽으면 오버플로우 취약 신호.
        "likely_overflow": baseline_ok and "overflow" in crashing,
        "likely_format": baseline_ok and "format" in crashing,
        "results": results,
    }


__all__ = ["locate_wine", "pe_crash_triage", "run_pe"]
