"""프로세스 메모리 스냅샷/덤프 — 언패킹·복호화 재구성 보조 (Phase 6D).

패커/난독화 바이너리는 원래 코드·데이터를 **런타임에 메모리로 풀어놓는다**. 이
모듈은 :class:`sandbox.debugger.DebugSession` 으로 대상을 원하는 지점(브레이크포인트
또는 N 스텝)까지 실행한 뒤 매핑 영역을 읽어, 각 영역의 크기·권한·SHA-256·엔트로피와
(용량 제한 안에서) 원시 바이트(hex)를 담은 스냅샷을 만든다. :mod:`sandbox.runtime_strings`
가 '문자열'만 뽑는 것과 달리, 여기서는 재구성에 쓸 **원시 영역 바이트**를 돌려준다.

.. warning::
   신뢰할 수 없는 바이너리를 **실행**한다. 서비스 계층이 샌드박스 실행 게이트+격리
   마커를 강제한다(:mod:`sandbox.debugger` 와 동일 트러스트 모델).
"""

from __future__ import annotations

import hashlib

from pwnable_lab.analyzer.entropy import shannon_entropy
from pwnable_lab.sandbox.debugger import DebugSession, StopEvent
from pwnable_lab.sandbox.runner import SandboxLimits

# 영역 선택 프리셋.
_SELECTORS = {"writable", "code", "all"}
# 파일 백업이 아닌(런타임 생성) 매핑 이름.
_ANON_PATHS = {"", "[heap]", "[stack]", "[anon]"}
# 스냅샷 총량·영역별 hex 상한(과도한 pread/JSON 방지).
_DEFAULT_MAX_TOTAL = 4 << 20  # 4 MiB
_PER_REGION_HEX_CAP = 256 << 10  # 영역당 hex 로 반환하는 최대 바이트


def dump_memory(
    binary_path: str,
    *,
    breakpoint: int | None = None,
    steps: int = 0,
    select: str = "writable",
    max_total_bytes: int = _DEFAULT_MAX_TOTAL,
    limits: SandboxLimits | None = None,
) -> dict:
    """대상을 실행해 선택한 메모리 영역의 스냅샷을 뜬다.

    ``select`` 는 ``"writable"``(쓰기 가능·익명 실행 = 언패킹 데이터, 기본),
    ``"code"``(실행 가능 매핑), ``"all"``(모든 읽기 가능 매핑) 중 하나. 각 영역은
    메타데이터(크기·권한·경로·sha256·엔트로피)와 총량 상한 안에서 원시 바이트(hex,
    영역당 상한 적용)를 담는다.
    """

    if select not in _SELECTORS:
        return {"attempted": False, "reason": f"bad-select:{select}"}

    limits = limits or SandboxLimits()
    session = DebugSession(binary_path, limits=limits)
    try:
        stopped = _advance(session, breakpoint, steps)
        if stopped.get("error"):
            return {"attempted": False, "reason": stopped["error"]}

        regions: list[dict] = []
        budget = max_total_bytes
        total = 0
        for region in session.maps():
            if not _selected(region, select):
                continue
            want = min(region["end"] - region["start"], budget)
            if want <= 0:
                break
            blob = session.read_region(region["start"], want)
            budget -= len(blob)
            total += len(blob)
            regions.append(_region_snapshot(region, blob))

        return {
            "attempted": True,
            "select": select,
            "stopped": stopped,
            "region_count": len(regions),
            "captured_bytes": total,
            "regions": regions,
        }
    finally:
        session.close()


def _selected(region: dict, select: str) -> bool:
    perms, path = region["perms"], region["path"]
    if select == "all":
        return True
    if select == "code":
        return "x" in perms
    # "writable": 쓰기 가능하거나 익명(런타임 데이터가 있을 곳).
    return "w" in perms or path in _ANON_PATHS


def _region_snapshot(region: dict, blob: bytes) -> dict:
    snap = {
        "start": f"0x{region['start']:x}",
        "end": f"0x{region['end']:x}",
        "perms": region["perms"],
        "path": region["path"],
        "size": region["end"] - region["start"],
        "captured": len(blob),
        "sha256": hashlib.sha256(blob).hexdigest() if blob else None,
        "entropy": round(shannon_entropy(blob), 4) if blob else None,
    }
    if blob:
        snap["hex"] = blob[:_PER_REGION_HEX_CAP].hex()
        snap["hex_truncated"] = len(blob) > _PER_REGION_HEX_CAP
    return snap


def _advance(session: DebugSession, breakpoint: int | None, steps: int) -> dict:
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


__all__ = ["dump_memory"]
