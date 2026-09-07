"""OEP(Original Entry Point) 후보 탐지 — 언패킹 재구성 보조 (Phase 6D).

로드맵의 "QEMU/rr/OEP/reconstruction assistance" 를 **외부 QEMU/rr 없이** 자체 ptrace
디버거(:class:`sandbox.debugger.DebugSession`)로 구현한다. 패커는 스텁이 압축/암호화된
코드를 **쓰기 가능한 메모리에 풀어놓은 뒤 그리로 점프**(tail jump)해 원래 진입점(OEP)
으로 실행을 넘긴다. 이 모듈은 단일스텝하며 제어가 **원래 파일 코드/라이브러리 밖의
쓰기 가능·익명 실행 영역**으로 처음 이전되는 지점을 OEP 후보로 보고한다.

정직성/한계: 단일스텝 기반이라 큰 스텁은 ``max_steps`` 안에 tail jump 에 도달하지
못할 수 있다(그때는 후보 없음 보고). 하드웨어 워치포인트/에뮬레이션이 아니므로
"보조 힌트"다. 정상(W^X 준수) 바이너리는 쓰기 가능 메모리를 실행하지 않으므로 후보가
없다 — 이는 참(오탐이 아님).

.. warning::
   신뢰할 수 없는 바이너리를 **실행**한다. 서비스 계층이 샌드박스 실행 게이트+격리
   마커를 강제한다(:mod:`sandbox.debugger` 와 동일 트러스트 모델).
"""

from __future__ import annotations

from pwnable_lab.sandbox.debugger import DebugSession
from pwnable_lab.sandbox.runner import SandboxLimits

# 파일 백업이 아닌(런타임 생성) 매핑 이름 — 여기서 실행되면 언패킹 코드로 본다.
_ANON_PATHS = {"", "[heap]", "[stack]", "[anon]"}


def find_oep_candidate(
    binary_path: str,
    *,
    start: int | None = None,
    max_steps: int = 200_000,
    limits: SandboxLimits | None = None,
) -> dict:
    """단일스텝하며 쓰기 가능·익명 실행 영역으로의 첫 제어 이전(OEP 후보)을 찾는다.

    ``start`` 가 주어지면 그 주소(브레이크포인트)까지 빠르게 진행한 뒤 단일스텝을
    시작한다(패커 스텁 진입점 또는 startup 이후). 반환에는 OEP 후보 주소(있으면)와
    관측 지점·스텝 수가 담긴다.
    """

    limits = limits or SandboxLimits()
    session = DebugSession(binary_path, limits=limits)
    try:
        if start is not None:
            if not session.set_breakpoint(start):
                return {"attempted": False, "reason": "start-unset"}
            event = session.cont()
            if event.reason != "breakpoint":
                return {"attempted": False, "reason": f"start-not-hit:{event.reason}"}
            session.remove_breakpoint(start)

        # 시작 시점의 실행 가능 매핑(원래 코드+로더+라이브러리)을 "알려진 코드"로 기록.
        known = _exec_ranges(session)

        steps = 0
        final_reason = "max-steps"
        while steps < max_steps:
            event = session.step()
            steps += 1
            if event.reason in {"exited", "signal", "timeout"}:
                final_reason = event.reason
                break
            rip = event.rip
            if rip is None or _in_ranges(rip, known):
                continue
            # 알려진 코드 밖으로 이전 — 현재 RIP 이 속한 매핑을 분류한다.
            region = _region_of(session, rip)
            if region is None:
                continue
            if "w" in region["perms"] or region["path"] in _ANON_PATHS:
                return {
                    "attempted": True,
                    "oep_candidate": f"0x{rip:x}",
                    "region": _region_summary(region),
                    "steps": steps,
                    "reason": "tail-jump-to-writable-exec",
                }
            # 새 파일 백업 실행 영역(예: libc)이면 알려진 코드에 더하고 계속.
            known.append((region["start"], region["end"]))

        return {
            "attempted": True,
            "oep_candidate": None,
            "steps": steps,
            "reason": final_reason,
        }
    finally:
        session.close()


def _exec_ranges(session: DebugSession) -> list[tuple[int, int]]:
    """ "알려진 정상 코드" 실행 범위: 실행 가능하고 **쓰기 불가**한 파일 백업 매핑.

    쓰기 가능·익명 실행 영역은 언패킹 대상 후보이므로 known 에서 제외한다(이미 mmap
    된 RWX 페이지가 known 에 들어가면 tail jump 를 못 잡는다).
    """

    return [
        (r["start"], r["end"])
        for r in session.maps()
        if "x" in r["perms"] and "w" not in r["perms"] and r["path"] not in _ANON_PATHS
    ]


def _in_ranges(addr: int, ranges: list[tuple[int, int]]) -> bool:
    return any(start <= addr < end for start, end in ranges)


def _region_of(session: DebugSession, addr: int) -> dict | None:
    for region in session.maps():
        if region["start"] <= addr < region["end"]:
            return region
    return None


def _region_summary(region: dict) -> dict:
    return {
        "start": f"0x{region['start']:x}",
        "end": f"0x{region['end']:x}",
        "perms": region["perms"],
        "path": region["path"],
    }


__all__ = ["find_oep_candidate"]
