"""실행 트레이스 (rr-lite) — 재구성 보조 (Phase 6D 후속).

외부 QEMU/rr 없이 자체 ptrace 디버거(:class:`sandbox.debugger.DebugSession`)로
바이너리를 단일스텝하며 **대상 자신의 실행 영역 안**에서 실행된 명령 주소를 기록한다.
트레이스는 연속 중복을 접고(같은 주소 반복 제거) 상한을 둬 컴팩트하게 유지한다.

.. warning::
   신뢰할 수 없는 바이너리를 **실행**한다 — 서비스 계층이 샌드박스 실행 게이트+격리
   마커를 강제한다(:mod:`sandbox.runtime_strings`·:mod:`sandbox.oep` 와 동일 모델).
"""

from __future__ import annotations

import os

from pwnable_lab.sandbox.debugger import DebugSession
from pwnable_lab.sandbox.runner import SandboxLimits

# 반환하는 trace 항목 수 상한(대상 실행 영역 안 주소만, 연속 중복 제거 후).
_TRACE_CAP = 4000


def execution_trace(
    binary_path: str,
    *,
    start: int | None = None,
    max_steps: int = 20_000,
    limits: SandboxLimits | None = None,
) -> dict:
    """단일스텝하며 대상 실행 영역 안 명령 주소를 기록한다.

    ``start`` 가 주어지면 그 주소(브레이크포인트)까지 진행한 뒤 스텝을 시작한다.
    반환은 스텝 수·고유 주소 수·트레이스(상한)·관측 종료 지점·커버리지 주소 수다.
    """

    limits = limits or SandboxLimits()
    session = DebugSession(binary_path, limits=limits)
    try:
        target_ranges = _target_exec_ranges(session, binary_path)

        if start is not None:
            if not session.set_breakpoint(start):
                return {"attempted": False, "reason": "start-unset"}
            event = session.cont()
            if event.reason != "breakpoint":
                return {"attempted": False, "reason": f"start-not-hit:{event.reason}"}
            session.remove_breakpoint(start)

        trace: list[int] = []
        coverage: set[int] = set()
        last: int | None = None
        steps = 0
        final_reason = "max-steps"
        while steps < max_steps:
            event = session.step()
            steps += 1
            if event.reason in {"exited", "signal", "timeout"}:
                final_reason = event.reason
                break
            rip = event.rip
            if rip is None or not _in_ranges(rip, target_ranges):
                continue
            coverage.add(rip)
            if rip != last:  # 연속 중복 접기
                if len(trace) < _TRACE_CAP:
                    trace.append(rip)
                last = rip

        return {
            "attempted": True,
            "steps": steps,
            "unique_addresses": len(coverage),
            "coverage_addresses": len(coverage),
            "trace": [f"0x{a:x}" for a in trace],
            "trace_truncated": len(coverage) > _TRACE_CAP,
            "stopped": {"reason": final_reason},
        }
    finally:
        session.close()


def _target_exec_ranges(
    session: DebugSession, binary_path: str
) -> list[tuple[int, int]]:
    """대상 바이너리 자신의 실행 매핑 범위. 매칭 실패 시 모든 실행 매핑으로 폴백."""

    real = os.path.realpath(binary_path)
    own: list[tuple[int, int]] = []
    any_exec: list[tuple[int, int]] = []
    for region in session.maps():
        if "x" not in region["perms"]:
            continue
        any_exec.append((region["start"], region["end"]))
        path = region["path"]
        if path and os.path.realpath(path) == real:
            own.append((region["start"], region["end"]))
    return own or any_exec


def _in_ranges(addr: int, ranges: list[tuple[int, int]]) -> bool:
    return any(start <= addr < end for start, end in ranges)


__all__ = ["execution_trace"]
