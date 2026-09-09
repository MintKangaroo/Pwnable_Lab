"""힙 인스펙터(heap 익스 보조): glibc 청크·tcache 파싱 검증."""

from __future__ import annotations

import platform
import shutil
import subprocess

import pytest

from pwnable_lab.api.services import AnalysisService
from pwnable_lab.config import Settings
from pwnable_lab.elf.parser import parse_elf
from pwnable_lab.sandbox import SandboxLimits
from pwnable_lab.sandbox.heap import inspect_heap

_SUPPORTED = platform.system() == "Linux" and platform.machine() in {"x86_64", "AMD64"}
_HAVE_GCC = shutil.which("gcc") is not None

# a(0x18)·b(0x28)·c(0x38) malloc 후 a·b free → tcache bin 0·1 채움.
_SRC = """
#include <stdlib.h>
#include <string.h>
void checkpoint(void){ }
int main(void){
  char *a=malloc(0x18); strcpy(a,"AAAA");
  char *b=malloc(0x28); strcpy(b,"BBBB");
  char *c=malloc(0x38);
  free(a); free(b);
  checkpoint();
  return (int)(size_t)c;
}
"""

_gated = pytest.mark.skipif(
    not (_SUPPORTED and _HAVE_GCC), reason="Linux/x86-64 + gcc 필요(실제 실행)"
)


def _build(tmp_path) -> tuple[str, int]:
    csrc = tmp_path / "heap.c"
    csrc.write_text(_SRC)
    out = tmp_path / "heap"
    subprocess.run(
        ["gcc", "-no-pie", "-O0", "-o", str(out), str(csrc)],
        check=True,
        capture_output=True,
    )
    cp = next(
        s.addr for s in parse_elf(out.read_bytes()).symbols if s.name == "checkpoint"
    )
    return str(out), int(cp)


@_gated
def test_inspect_heap_chunks_and_tcache(tmp_path):
    path, cp = _build(tmp_path)
    result = inspect_heap(path, breakpoint=cp, limits=SandboxLimits())
    assert result["attempted"] is True
    assert result["stopped"]["reason"] == "breakpoint"

    # 첫 청크는 tcache_perthread_struct, 이어서 0x20/0x30/0x40 청크가 있어야 한다.
    sizes = [c["size"] for c in result["chunks"]]
    assert result["chunks"][0]["tcache_struct"] is True
    assert "0x20" in sizes and "0x30" in sizes and "0x40" in sizes

    # tcache: bin 0(0x20)·1(0x30) 이 각각 1개(a·b free).
    by_index = {b["index"]: b for b in result["tcache"]}
    assert by_index[0]["count"] == 1 and by_index[0]["chunk_size"] == "0x20"
    assert by_index[1]["count"] == 1 and by_index[1]["chunk_size"] == "0x30"
    assert by_index[0]["head_hex"] is not None


@_gated
def test_inspect_heap_breakpoint_unset(tmp_path):
    path, _ = _build(tmp_path)
    result = inspect_heap(path, breakpoint=0x1, limits=SandboxLimits())
    assert result["attempted"] is False
    assert result["reason"] == "breakpoint-unset"


@_gated
def test_service_heap_inspect_gated(tmp_path):
    path, cp = _build(tmp_path)
    service = AnalysisService(Settings(sandbox_execution_enabled=True))
    result = service.heap_inspect(open(path, "rb").read(), breakpoint=cp)
    assert result["attempted"] is True
    assert result["chunk_count"] >= 4
    assert any(b["index"] == 0 for b in result["tcache"])


# fastbin(2개)+unsorted(1개)+tcache(7개) 를 한 스냅샷에 만드는 골든.
_SRC_BINS = """
#include <stdlib.h>
void checkpoint(void){ }
int main(void){
  void *big = malloc(0x430);
  void *g1  = malloc(0x20);
  void *s[9];
  for(int i=0;i<9;i++) s[i]=malloc(0x10);
  void *g2 = malloc(0x20);
  (void)g1;(void)g2;
  free(big);
  for(int i=0;i<9;i++) free(s[i]);
  checkpoint();
  return 0;
}
"""


def _build_bins(tmp_path) -> tuple[str, int]:
    csrc = tmp_path / "bins.c"
    csrc.write_text(_SRC_BINS)
    out = tmp_path / "bins"
    subprocess.run(
        ["gcc", "-no-pie", "-O0", "-o", str(out), str(csrc)],
        check=True,
        capture_output=True,
    )
    cp = next(
        s.addr for s in parse_elf(out.read_bytes()).symbols if s.name == "checkpoint"
    )
    return str(out), int(cp)


@_gated
def test_inspect_heap_fastbin_unsorted_arena(tmp_path):
    path, cp = _build_bins(tmp_path)
    result = inspect_heap(path, breakpoint=cp, limits=SandboxLimits())
    assert result["attempted"] is True

    # unsorted: PREV_INUSE 로 감지된 free 청크가 main_arena 를 가리킨다.
    unsorted = [c for c in result["free_chunks"] if c["bin"] == "unsorted"]
    assert len(unsorted) == 1
    assert unsorted[0]["links_to_arena"] is True
    assert int(unsorted[0]["size"], 16) >= 0x430

    # arena 복구 + fastbin: 0x20 bin 에 2개(7개는 tcache 로 가고 2개가 넘침).
    arena = result["arena"]
    assert arena is not None
    assert arena["recovered_from"] == "unsorted-fd"
    fb0 = next(b for b in arena["fastbins"] if b["index"] == 0)
    assert fb0["chunk_size"] == "0x20"
    assert fb0["count"] == 2
    assert len(fb0["chain"]) == 2

    # tcache 0x20 bin 은 7개(가득).
    tc0 = next(b for b in result["tcache"] if b["index"] == 0)
    assert tc0["count"] == 7


@_gated
def test_inspect_heap_no_free_chunks_arena_none(tmp_path):
    # 기존 골든(free 는 tcache 로만) → PREV_INUSE-free 없음 → arena 복구 불가(None).
    path, cp = _build(tmp_path)
    result = inspect_heap(path, breakpoint=cp, limits=SandboxLimits())
    assert result["arena"] is None
    assert all(c["bin"] != "unsorted" for c in result["free_chunks"])


def test_bin_kind_classification():
    from pwnable_lab.sandbox.heap import _bin_kind

    assert _bin_kind(0x20) == "fastbin"
    assert _bin_kind(0x80) == "fastbin"
    assert _bin_kind(0x90) == "smallbin"
    assert _bin_kind(0x3F0) == "smallbin"
    assert _bin_kind(0x400) == "largebin"
    assert _bin_kind(0x1000) == "largebin"


def test_free_chunks_smallbin_when_fd_in_heap():
    # in_use=False 이고 fd 가 힙 내부를 가리키는 free 청크 → bin=크기기반(unsorted 아님).
    from pwnable_lab.sandbox.heap import _free_chunks

    base = 0x400000
    # 힙 blob: 한 청크(off 0)를 free 로, fd 는 힙 내부(base+0x40)로.
    import struct as _s

    blob = bytearray(0x200)
    _s.pack_into("<QQ", blob, 0x10, base + 0x40, base + 0x40)  # fd/bk in-heap
    chunks = [
        {"addr": f"0x{base:x}", "size": "0x90", "in_use": False},
        {"addr": f"0x{base + 0x90:x}", "size": "0x20", "in_use": True},
    ]
    out = _free_chunks(base, bytes(blob), chunks)
    assert len(out) == 1
    assert out[0]["bin"] == "smallbin"
    assert out[0]["links_to_arena"] is False


@_gated
def test_inspect_heap_libc_leak(tmp_path):
    from pwnable_lab.sandbox.debugger import DebugSession
    from pwnable_lab.sandbox.heap import inspect_heap_session

    path, cp = _build_bins(tmp_path)
    # main_arena 를 담은 매핑의 파일을 ground truth 로: 그 path 의 최소 start 가 libc base.
    session = DebugSession(path, limits=SandboxLimits())
    try:
        session.set_breakpoint(cp)
        session.cont()
        state = inspect_heap_session(session)
        main_arena = int(state["arena"]["main_arena"], 16)
        containing = next(
            m for m in session.maps() if m["start"] <= main_arena < m["end"]
        )
        real_path = containing["path"]
        real_base = min(
            m["start"] for m in session.maps() if m.get("path") == real_path
        )
    finally:
        session.close()

    leak = state["arena"]["libc_leak"]
    assert leak is not None
    assert "libc" in leak["path"]
    assert leak["path"] == real_path
    assert int(leak["libc_base"], 16) == real_base
    # main_arena = libc_base + offset 가 일관.
    assert int(leak["libc_base"], 16) + int(leak["main_arena_offset"], 16) == main_arena
    # leaked_pointer(UAF 로 읽는 값) = unsorted fd.
    assert leak["leaked_pointer"] == state["free_chunks"][0]["fd"]


def test_libc_leak_none_when_arena_unmapped():
    from pwnable_lab.sandbox.heap import _libc_leak

    class _FakeSession:
        def maps(self):
            return [{"start": 0x1000, "end": 0x2000, "path": "[heap]"}]

    # main_arena 가 어느 매핑에도 없으면 leak 계산 불가 → None(정직).
    assert _libc_leak(_FakeSession(), 0x7FFFDEAD0000) is None


def test_libc_leak_computes_base_from_fake_maps():
    from pwnable_lab.sandbox.heap import _libc_leak

    class _FakeSession:
        def maps(self):
            return [
                {"start": 0x7F0000, "end": 0x7F1000, "path": "/lib/libc.so.6"},
                {"start": 0x7F1000, "end": 0x7F3000, "path": "/lib/libc.so.6"},
            ]

    leak = _libc_leak(_FakeSession(), 0x7F2000)  # 두 번째 매핑 안
    assert leak["libc_base"] == "0x7f0000"  # 같은 path 최소 start
    assert leak["main_arena_offset"] == "0x2000"
    assert leak["leaked_pointer"] == f"0x{0x7F2000 + 0x60:x}"
