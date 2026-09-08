"""힙 인스펙터 — 실행 중 glibc 힙 청크·tcache 를 파싱 (heap 익스플로잇 보조).

heap 챌린지(tcache poisoning·UAF·double-free)는 청크 레이아웃과 free-list 상태를
이해해야 한다. 이 모듈은 :class:`sandbox.debugger.DebugSession` 으로 대상을 원하는
지점까지 실행한 뒤 ``[heap]`` 영역의 malloc 청크를 크기 필드로 순회하고, tcache
per-thread 구조의 bin 카운트·free-list 헤드를 파싱한다(pwndbg 의 heap/bins 축약).

glibc 2.32+ safe-linking 은 free 청크의 ``fd`` 를 ``ptr ^ (chunk_addr >> 12)`` 로
난독화한다. free-list 를 따라갈 때 이를 역산한다.
"""

from __future__ import annotations

import struct

from pwnable_lab.sandbox.debugger import DebugSession, StopEvent
from pwnable_lab.sandbox.runner import SandboxLimits

_TCACHE_BINS = 64
_CHUNK_HDR = 0x10  # prev_size + size
# tcache_perthread_struct: uint16 counts[64] then void* entries[64].
_COUNTS_OFF = 0x10  # 첫 청크(tcache struct) 데이터 시작 = heap_base + 0x10
_ENTRIES_OFF = _COUNTS_OFF + _TCACHE_BINS * 2


def inspect_heap(
    binary_path: str,
    *,
    breakpoint: int | None = None,
    steps: int = 0,
    max_chunks: int = 256,
    limits: SandboxLimits | None = None,
) -> dict:
    """대상을 실행해 힙 청크·tcache 상태를 덤프한다(브레이크포인트 또는 N 스텝 후)."""

    limits = limits or SandboxLimits()
    session = DebugSession(binary_path, limits=limits)
    try:
        stopped = _advance(session, breakpoint, steps)
        if stopped.get("error"):
            return {"attempted": False, "reason": stopped["error"]}

        heap = next((m for m in session.maps() if m["path"] == "[heap]"), None)
        if heap is None:
            return {"attempted": False, "reason": "no-heap", "stopped": stopped}
        base, end = heap["start"], heap["end"]
        blob = session.read_region(base, min(end - base, 1 << 20))

        chunks = _walk_chunks(base, blob, max_chunks)
        tcache = _parse_tcache(base, blob)
        return {
            "attempted": True,
            "heap": {"start": f"0x{base:x}", "end": f"0x{end:x}"},
            "stopped": stopped,
            "chunk_count": len(chunks),
            "chunks": chunks,
            "tcache": tcache,
        }
    finally:
        session.close()


def _walk_chunks(base: int, blob: bytes, max_chunks: int) -> list[dict]:
    """힙 시작부터 size 필드로 청크를 순회한다(첫 청크=tcache struct 로 표시)."""

    chunks: list[dict] = []
    pos = 0
    while pos + _CHUNK_HDR <= len(blob) and len(chunks) < max_chunks:
        _prev, size = struct.unpack_from("<QQ", blob, pos)
        real = size & ~0xF
        if real < 0x10:
            break
        chunks.append(
            {
                "addr": f"0x{base + pos:x}",
                "size": f"0x{real:x}",
                "prev_inuse": bool(size & 1),
                "is_mmapped": bool(size & 2),
                "tcache_struct": pos == 0,
            }
        )
        pos += real
    return chunks


def _parse_tcache(base: int, blob: bytes) -> list[dict]:
    """tcache per-thread 구조의 bin 카운트·free-list 헤드를 파싱한다(count>0 만)."""

    if len(blob) < _ENTRIES_OFF + _TCACHE_BINS * 8:
        return []
    counts = struct.unpack_from(f"<{_TCACHE_BINS}H", blob, _COUNTS_OFF)
    entries = struct.unpack_from(f"<{_TCACHE_BINS}Q", blob, _ENTRIES_OFF)
    bins: list[dict] = []
    for i, count in enumerate(counts):
        if count == 0:
            continue
        chunk_size = 0x20 + i * 0x10  # bin i → 청크 크기
        head = entries[i]
        bins.append(
            {
                "index": i,
                "chunk_size": f"0x{chunk_size:x}",
                "count": count,
                "head_hex": f"0x{head:x}" if head else None,
            }
        )
    return bins


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


__all__ = ["inspect_heap"]
