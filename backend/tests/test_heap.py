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
