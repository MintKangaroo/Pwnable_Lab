"""런타임 strings — 실행 중 메모리에서만 나타나는 문자열 발굴 (Phase 6C).

정적 strings(:func:`analyzer.strings.extract_strings`)는 파일에 이미 있는 문자열만
본다. 패커/난독화 바이너리는 문자열을 **런타임에 복호화·재구성**하므로 정적으로는
안 보인다. 이 모듈은 :class:`sandbox.debugger.DebugSession` 으로 대상을 원하는 지점
(브레이크포인트 또는 N 스텝)까지 실행시킨 뒤 쓰기 가능/익명 메모리 영역을 훑어
ASCII 문자열을 뽑고, **정적 strings 에 없는 것만** 골라 런타임 전용 문자열로 보고한다.

.. warning::
   신뢰할 수 없는 바이너리를 **실행**한다. 서비스 계층이 샌드박스 실행 게이트+격리
   마커를 강제한다(:mod:`sandbox.debugger` 와 동일 트러스트 모델).
"""

from __future__ import annotations

from pathlib import Path

from pwnable_lab.analyzer.strings import extract_strings
from pwnable_lab.sandbox.debugger import DebugSession, StopEvent
from pwnable_lab.sandbox.runner import SandboxLimits

# 런타임 메모리 스캔 총량 상한(과도한 PEEK/pread 방지).
_DEFAULT_MAX_BYTES = 1 << 20  # 1 MiB
# 파일 백업이 아닌(런타임 데이터일 가능성이 큰) 특수 매핑 이름.
_ANON_PATHS = {"", "[heap]", "[stack]", "[anon]", "[bss]"}
_PRINTABLE = set(range(0x20, 0x7F))


def runtime_strings(
    binary_path: str,
    *,
    breakpoint: int | None = None,
    steps: int = 0,
    min_length: int = 4,
    max_total_bytes: int = _DEFAULT_MAX_BYTES,
    limits: SandboxLimits | None = None,
) -> dict:
    """대상을 실행해 런타임에만 나타나는 문자열을 발굴한다.

    ``breakpoint`` 가 주어지면 그 주소에서 멈춘 뒤, 아니면 ``steps`` 만큼 단일스텝한
    뒤(0 이면 exec-stop 직후) 쓰기 가능/익명 메모리를 훑는다. 반환은 정적 strings 에
    없는 런타임 전용 문자열 목록과 관측 지점 정보다.
    """

    data = Path(binary_path).read_bytes()
    static = {s.value for s in extract_strings(data, min_length=min_length)}

    limits = limits or SandboxLimits()
    session = DebugSession(binary_path, limits=limits)
    try:
        stopped = _advance(session, breakpoint, steps)
        if stopped.get("error"):
            return {"attempted": False, "reason": stopped["error"]}

        found: set[str] = set()
        budget = max_total_bytes
        scanned = 0
        for region in session.maps():
            if budget <= 0:
                break
            # 정적으로 보이는 파일 백업 코드/상수는 건너뛰고, 쓰기 가능하거나 익명인
            # (런타임 데이터일) 영역만 훑는다.
            if "w" not in region["perms"] and region["path"] not in _ANON_PATHS:
                continue
            size = min(region["end"] - region["start"], budget)
            blob = session.read_region(region["start"], size)
            budget -= len(blob)
            scanned += len(blob)
            found.update(_ascii_runs(blob, min_length))

        runtime_only = sorted(s for s in found if s not in static)
        return {
            "attempted": True,
            "stopped": stopped,
            "scanned_bytes": scanned,
            "static_count": len(static),
            "runtime_only_count": len(runtime_only),
            "runtime_only": runtime_only[:2000],
        }
    finally:
        session.close()


def _advance(session: DebugSession, breakpoint: int | None, steps: int) -> dict:
    """세션을 관측 지점까지 진행시키고 StopEvent dict(또는 error)를 반환한다."""

    event: StopEvent | None = None
    if breakpoint is not None:
        if not session.set_breakpoint(breakpoint):
            return {"error": "breakpoint-unset"}
        event = session.cont()
        if event.reason != "breakpoint":
            return {"error": f"no-breakpoint-hit:{event.reason}"}
        return event.as_dict()
    for _ in range(max(steps, 0)):
        event = session.step()
        if event.reason in {"exited", "signal", "timeout"}:
            break
    return event.as_dict() if event is not None else {"reason": "exec-stop"}


def _ascii_runs(blob: bytes, min_length: int):
    """``blob`` 에서 최소 길이 이상의 출력 가능 ASCII 문자열 런을 만든다."""

    start = None
    for i, byte in enumerate(blob):
        if byte in _PRINTABLE:
            if start is None:
                start = i
        elif start is not None:
            if i - start >= min_length:
                yield blob[start:i].decode("ascii")
            start = None
    if start is not None and len(blob) - start >= min_length:
        yield blob[start:].decode("ascii")


__all__ = ["runtime_strings"]
