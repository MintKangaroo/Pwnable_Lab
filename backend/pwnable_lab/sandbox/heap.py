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

# glibc 2.26+(tcache) x86-64 malloc_state(main_arena) 레이아웃 오프셋.
# 경험적으로 확정: fastbinsY@+0x10(10개), top@+0x60, bin_at(1)=unsorted head=+0x60.
_ARENA_FASTBINS_OFF = 0x10
_ARENA_NFASTBINS = 10
_ARENA_TOP_OFF = 0x60
_ARENA_LASTREMAINDER_OFF = 0x68
# free 청크(unsorted/small/large)의 fd 는 bin_at(1)=main_arena+0x60 을 가리킨다.
_ARENA_UNSORTED_BIN_OFF = 0x60
_MAX_FASTBIN_CHAIN = 64  # 무한 루프 방지


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
        free_chunks = _free_chunks(base, blob, chunks)
        arena = _read_arena(session, base, end, free_chunks)
        return {
            "attempted": True,
            "heap": {"start": f"0x{base:x}", "end": f"0x{end:x}"},
            "stopped": stopped,
            "chunk_count": len(chunks),
            "chunks": chunks,
            "tcache": tcache,
            "free_chunks": free_chunks,
            "arena": arena,
        }
    finally:
        session.close()


def _walk_chunks(base: int, blob: bytes, max_chunks: int) -> list[dict]:
    """힙 시작부터 size 필드로 청크를 순회한다(첫 청크=tcache struct 로 표시).

    각 청크에 ``in_use`` 를 붙인다: **다음** 청크의 PREV_INUSE 비트가 이 청크의
    할당 여부를 알려준다(0 이면 free). 단 tcache/fastbin 으로 free 된 청크는 glibc
    가 PREV_INUSE 를 그대로 두므로 여기서 in_use=True 로 보인다(그건 tcache/fastbin
    파싱으로 따로 다룬다). 마지막(top) 청크는 다음이 없어 ``in_use=None``.
    """

    raw: list[tuple[int, int, bool]] = []  # (pos, real_size, prev_inuse)
    pos = 0
    while pos + _CHUNK_HDR <= len(blob) and len(raw) < max_chunks:
        _prev, size = struct.unpack_from("<QQ", blob, pos)
        real = size & ~0xF
        if real < 0x10:
            break
        raw.append((pos, real, bool(size & 1)))
        pos += real

    chunks: list[dict] = []
    for i, (p, real, prev_inuse) in enumerate(raw):
        next_prev_inuse = raw[i + 1][2] if i + 1 < len(raw) else None
        in_use = None if next_prev_inuse is None else next_prev_inuse
        _prev, size = struct.unpack_from("<QQ", blob, p)
        chunks.append(
            {
                "addr": f"0x{base + p:x}",
                "size": f"0x{real:x}",
                "prev_inuse": prev_inuse,
                "is_mmapped": bool(size & 2),
                "in_use": in_use,
                "tcache_struct": p == 0,
            }
        )
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


def _bin_kind(size: int) -> str:
    """청크 크기로 bin 종류를 유추한다(default tcache/fastbin 상한 기준)."""

    if size <= 0x80:
        return "fastbin"  # 또는 tcache(tcache 파싱이 우선)
    if size < 0x400:
        return "smallbin"
    return "largebin"


def _free_chunks(base: int, blob: bytes, chunks: list[dict]) -> list[dict]:
    """PREV_INUSE 로 감지되는 free 청크(unsorted/small/large)를 fd/bk 와 함께 모은다.

    tcache/fastbin 은 PREV_INUSE 를 남기므로 여기 안 잡힌다(tcache/fastbins 로 별도
    보고). fd/bk 가 힙 밖(=main_arena bin head)을 가리키면 unsorted 후보로 표시한다.
    """

    heap_end = base + len(blob)
    out: list[dict] = []
    for c in chunks:
        if c["in_use"] is not False:
            continue
        addr = int(c["addr"], 16)
        off = addr - base
        if off + 0x20 > len(blob):
            continue
        fd, bk = struct.unpack_from("<QQ", blob, off + _CHUNK_HDR)
        points_out = not (base <= fd < heap_end)
        out.append(
            {
                "addr": c["addr"],
                "size": c["size"],
                "fd": f"0x{fd:x}",
                "bk": f"0x{bk:x}",
                "bin": ("unsorted" if points_out else _bin_kind(int(c["size"], 16))),
                "links_to_arena": points_out,
            }
        )
    return out


def _recover_main_arena(
    session: DebugSession, base: int, heap_end: int, free_chunks: list[dict]
) -> int | None:
    """unsorted free 청크의 fd(=bin_at(1)) 에서 main_arena 주소를 복구·검증한다.

    fd 가 힙 밖 rw 매핑(libc data)을 가리키면 ``main_arena = fd - 0x60``. 복구값이
    실제 rw- 매핑 안에 있고 힙이 아니면 반환, 아니면 None(정직).
    """

    candidate = next(
        (int(c["fd"], 16) for c in free_chunks if c["links_to_arena"]), None
    )
    if candidate is None:
        return None
    main_arena = candidate - _ARENA_UNSORTED_BIN_OFF
    for m in session.maps():
        if (
            m["start"] <= main_arena < m["end"]
            and m["path"] != "[heap]"
            and "w" in m.get("perms", "")
        ):
            return main_arena
    return None


def _walk_fastbin(session: DebugSession, head: int) -> list[str]:
    """fastbin 체인을 따라간다(safe-linking: next = *(p+0x10) ^ (p>>12))."""

    chain: list[str] = []
    node = head
    seen: set[int] = set()
    while node and node not in seen and len(chain) < _MAX_FASTBIN_CHAIN:
        seen.add(node)
        chain.append(f"0x{node:x}")
        try:
            raw = session.read_region(node + _CHUNK_HDR, 8)
        except OSError:
            break
        stored = struct.unpack("<Q", raw)[0]
        node = stored ^ (node >> 12) if stored else 0
    return chain


def _read_arena(
    session: DebugSession, base: int, heap_end: int, free_chunks: list[dict]
) -> dict | None:
    """main_arena 를 복구해 fastbinsY·top·last_remainder 를 읽는다(불가 시 None)."""

    main_arena = _recover_main_arena(session, base, heap_end, free_chunks)
    if main_arena is None:
        return None
    try:
        fb_blob = session.read_region(
            main_arena + _ARENA_FASTBINS_OFF, _ARENA_NFASTBINS * 8
        )
        top = struct.unpack("<Q", session.read_region(main_arena + _ARENA_TOP_OFF, 8))[
            0
        ]
        last_rem = struct.unpack(
            "<Q", session.read_region(main_arena + _ARENA_LASTREMAINDER_OFF, 8)
        )[0]
    except OSError:
        return None

    heads = struct.unpack(f"<{_ARENA_NFASTBINS}Q", fb_blob)
    fastbins: list[dict] = []
    for i, head in enumerate(heads):
        if not head:
            continue
        chain = _walk_fastbin(session, head)
        fastbins.append(
            {
                "index": i,
                "chunk_size": f"0x{0x20 + i * 0x10:x}",
                "head_hex": f"0x{head:x}",
                "count": len(chain),
                "chain": chain,
            }
        )
    return {
        "main_arena": f"0x{main_arena:x}",
        "recovered_from": "unsorted-fd",
        "top": f"0x{top:x}",
        "last_remainder": f"0x{last_rem:x}" if last_rem else None,
        "fastbins": fastbins,
    }


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
