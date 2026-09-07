"""포맷스트링 %n GOT 덮어쓰기 자동 익스: printf(user_input) → GOT → win → 셸 증명."""

from __future__ import annotations

import platform
import shutil
import subprocess

import pytest

from pwnable_lab.analyzer.strategy import got_overwrite_targets, ret2win_target
from pwnable_lab.api.services import AnalysisService
from pwnable_lab.config import Settings
from pwnable_lab.elf.parser import parse_elf
from pwnable_lab.payload.pack import build_fmtstr_write, p64
from pwnable_lab.sandbox import SandboxLimits
from pwnable_lab.sandbox.fmtwrite import auto_fmt_got_overwrite

_SUPPORTED = platform.system() == "Linux" and platform.machine() in {"x86_64", "AMD64"}
_HAVE_GCC = shutil.which("gcc") is not None

# 루프 안에서 사용자 입력을 그대로 printf 로 넘기는 포맷스트링 취약점. win 은 system
# 을 호출하므로 ret2win_target 이 리다이렉트 대상으로 감지한다. read 로 입력을 받아
# null 바이트를 포함한 payload 도 잘리지 않는다.
_FMT_SRC = r"""
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void win(void){ system("/bin/sh"); }
int main(void){
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 2, 0);
  char buf[200];
  while(1){
    int n = read(0, buf, sizeof buf - 1);
    if(n <= 0) break;
    buf[n] = 0;
    printf(buf);
    fflush(stdout);
  }
  return 0;
}
"""

# win 함수가 없어 리다이렉트 대상이 없는 포맷스트링 바이너리.
_NO_WIN_SRC = r"""
#include <stdio.h>
#include <unistd.h>
int main(void){
  setvbuf(stdout, 0, 2, 0);
  char buf[200];
  int n = read(0, buf, sizeof buf - 1);
  if(n > 0){ buf[n] = 0; printf(buf); }
  return 0;
}
"""

_gated = pytest.mark.skipif(
    not (_SUPPORTED and _HAVE_GCC), reason="Linux/x86-64 + gcc 필요(실제 실행)"
)


def _compile(tmp_path, src: str, name: str, *, pie: bool = False) -> str:
    csrc = tmp_path / f"{name}.c"
    csrc.write_text(src)
    out = tmp_path / name
    flags = ["-fno-stack-protector", "-pie" if pie else "-no-pie"]
    subprocess.run(
        ["gcc", *flags, "-o", str(out), str(csrc)],
        check=True,
        capture_output=True,
    )
    return str(out)


# --- build_fmtstr_write 단위(컴파일 불필요) ---------------------------------


def test_build_fmtstr_write_structure():
    got, win = 0x404020, 0x4011B6
    payload = build_fmtstr_write(6, {got: win})
    # 지시자에 %hhn 이 6개(하위 6바이트) 있고, 목적 주소들이 뒤에 붙는다.
    assert payload.count(b"$hhn") == 6
    # 각 바이트 대상 주소(got..got+5)가 payload 끝의 주소 목록에 8바이트로 존재한다.
    for i in range(6):
        assert p64(got + i) in payload
    # 지시자 부분은 8바이트 정렬(주소가 qword 경계에 오도록).
    fmt_len = payload.index(p64(got))
    assert fmt_len % 8 == 0


def test_build_fmtstr_write_validates_args():
    with pytest.raises(ValueError):
        build_fmtstr_write(0, {0x404020: 0x401000})
    with pytest.raises(ValueError):
        build_fmtstr_write(6, {})
    with pytest.raises(ValueError):
        build_fmtstr_write(6, {0x404020: 0x401000}, value_bytes=0)


# --- 정적 재료 수집(컴파일 필요) --------------------------------------------


@_gated
def test_got_overwrite_targets_and_win(tmp_path):
    img = parse_elf(open(_compile(tmp_path, _FMT_SRC, "fmt_target"), "rb").read())
    win = ret2win_target(img)
    assert win is not None and win[0] == "win"
    syms = {s for s, _ in got_overwrite_targets(img)}
    # 루프가 호출하는 printf 는 GOT 후보에 반드시 있어야 한다.
    assert "printf" in syms
    # 각 후보는 유효한 GOT 주소를 가진다.
    for _sym, addr in got_overwrite_targets(img):
        assert addr > 0


# --- 코어 셸 증명(컴파일·실행 필요) ------------------------------------------


@_gated
def test_auto_fmt_got_overwrite_proves_shell(tmp_path):
    path = _compile(tmp_path, _FMT_SRC, "fmt_target")
    res = auto_fmt_got_overwrite(path, limits=SandboxLimits())
    assert res["attempted"] is True
    assert res["technique"] == "fmt-got-overwrite"
    assert res["succeeded"] is True
    assert res["shell_proven"] is True
    assert res["reason"] == "shell-proven"
    assert res["target_name"] == "win"
    # 셸이 실제로 산술을 평가한 결과가 출력에 있어야 한다(입력 반사가 아닌 실행 증명).
    proof = res["shell_proof"]
    assert proof["shell_spawned"] is True
    assert proof["marker"] in proof["output"]


@_gated
def test_no_win_target_is_rejected(tmp_path):
    path = _compile(tmp_path, _NO_WIN_SRC, "no_win")
    res = auto_fmt_got_overwrite(path, limits=SandboxLimits())
    assert res["attempted"] is False
    assert res["reason"] == "no-redirect-target"


@_gated
def test_pie_is_rejected(tmp_path):
    path = _compile(tmp_path, _FMT_SRC, "fmt_pie", pie=True)
    res = auto_fmt_got_overwrite(path, limits=SandboxLimits())
    assert res["attempted"] is False
    assert res["reason"] == "pie-needs-base-leak"


# --- auto_exploit 폴백 선택(서비스 e2e) --------------------------------------


@_gated
def test_auto_exploit_falls_back_to_fmt_got_overwrite(tmp_path):
    path = _compile(tmp_path, _FMT_SRC, "fmt_target")
    service = AnalysisService(
        Settings(sandbox_execution_enabled=True, sandbox_executor="inprocess")
    )
    result = service.auto_exploit(open(path, "rb").read(), pattern_length=400)
    v = result["verification"]
    # 오버플로가 없으므로 오프셋 확정은 실패하고, 포맷스트링 GOT 덮어쓰기로 폴백한다.
    assert v["technique"] == "fmt-got-overwrite"
    assert v["succeeded"] is True
    assert v["shell_proven"] is True
