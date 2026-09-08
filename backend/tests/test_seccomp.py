"""seccomp-BPF 정적 분석(Phase 8): 필터 탐지·디코딩·전략 통합."""

from __future__ import annotations

import platform
import shutil
import struct
import subprocess

import pytest

from pwnable_lab.analyzer.seccomp import (
    _action_name,
    _decode,
    _locate_filter,
    _simulate,
    analyze_seccomp,
)
from pwnable_lab.analyzer.strategy import analyze_strategy
from pwnable_lab.elf.parser import parse_elf

_SUPPORTED = platform.system() == "Linux" and platform.machine() in {"x86_64", "AMD64"}
_HAVE_GCC = shutil.which("gcc") is not None

# execve/execveat 만 KILL, 나머지 ALLOW (blocklist 스타일). win()/system 포함.
_BLOCKLIST_SRC = """
#include <stdio.h>
#include <stdlib.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
void win(void){ system("/bin/sh"); }
static void install(void){
  static const struct sock_filter f[] = {
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS, 4),
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, AUDIT_ARCH_X86_64, 1, 0),
    BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS, 0),
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_execve, 2, 0),
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_execveat, 1, 0),
    BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
    BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
  };
  struct sock_fprog p = {.len=sizeof(f)/sizeof(f[0]), .filter=(struct sock_filter*)f};
  prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0); prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&p);
}
void vuln(void){ char b[64]; gets(b); }
int main(void){ install(); vuln(); return 0; }
"""

# 기본 KILL, read/write/open/openat/exit_group 만 ALLOW (allowlist 스타일).
_ALLOWLIST_SRC = """
#include <stdio.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
static void install(void){
  static const struct sock_filter f[] = {
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS, 4),
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, AUDIT_ARCH_X86_64, 1, 0),
    BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS, 0),
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_read, 5, 0),
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_write, 4, 0),
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_open, 3, 0),
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_openat, 2, 0),
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_exit_group, 1, 0),
    BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
    BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
  };
  struct sock_fprog p = {.len=sizeof(f)/sizeof(f[0]), .filter=(struct sock_filter*)f};
  prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0); prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&p);
}
int main(void){ install(); return 0; }
"""

_PLAIN_SRC = "#include <stdio.h>\nvoid vuln(void){ char b[64]; gets(b); }\nvoid win(void){}\nint main(void){ vuln(); return 0; }\n"


def _headers_ok(tmp_path) -> bool:
    if not (_SUPPORTED and _HAVE_GCC):
        return False
    probe = tmp_path / "probe.c"
    probe.write_text(
        "#include <linux/seccomp.h>\n#include <linux/filter.h>\nint main(void){return 0;}\n"
    )
    r = subprocess.run(
        ["gcc", "-o", str(tmp_path / "probe"), str(probe)], capture_output=True
    )
    return r.returncode == 0


def _compile(tmp_path, src: str, name: str) -> str:
    csrc = tmp_path / f"{name}.c"
    csrc.write_text(src)
    out = tmp_path / name
    subprocess.run(
        ["gcc", "-fno-stack-protector", "-no-pie", "-O0", "-o", str(out), str(csrc)],
        check=True,
        capture_output=True,
    )
    return str(out)


# --- BPF VM 단위(컴파일 불필요) ---------------------------------------------


def test_action_name_mapping():
    assert _action_name(0x7FFF0000) == "ALLOW"
    assert _action_name(0x80000000) == "KILL_PROCESS"
    assert _action_name(0x00050000) == "ERRNO"
    assert _action_name(None) == "UNKNOWN"


def test_simulate_blocklist_program():
    # ld[4];jeq ARCH? +1:kill; ld[0]; jeq execve?+1:allow; kill; allow
    prog = [
        (0x20, 0, 0, 4),
        (0x15, 1, 0, 0xC000003E),
        (0x06, 0, 0, 0x80000000),
        (0x20, 0, 0, 0),
        (0x15, 1, 0, 59),
        (0x06, 0, 0, 0x7FFF0000),
        (0x06, 0, 0, 0x80000000),
    ]
    assert _action_name(_simulate(prog, 59, 0xC000003E)) == "KILL_PROCESS"  # execve
    assert _action_name(_simulate(prog, 0, 0xC000003E)) == "ALLOW"  # read
    # 아키텍처 불일치 → kill.
    assert _action_name(_simulate(prog, 0, 0x40000003)) == "KILL_PROCESS"


def test_simulate_all_jump_ops_and_modes():
    # JGE/JGT/JSET/JA, LD IMM, MISC(tax/txa) 분기 커버.
    # ld [0](nr); jge 10?allow:kill
    jge = [
        (0x20, 0, 0, 0),
        (0x35, 1, 0, 10),
        (0x06, 0, 0, 0x80000000),
        (0x06, 0, 0, 0x7FFF0000),
    ]
    assert _action_name(_simulate(jge, 20, 0)) == "ALLOW"  # 20>=10
    assert _action_name(_simulate(jge, 5, 0)) == "KILL_PROCESS"
    # jgt
    jgt = [
        (0x20, 0, 0, 0),
        (0x25, 1, 0, 10),
        (0x06, 0, 0, 0x80000000),
        (0x06, 0, 0, 0x7FFF0000),
    ]
    assert _action_name(_simulate(jgt, 11, 0)) == "ALLOW"
    # jset (bit test)
    jset = [
        (0x20, 0, 0, 0),
        (0x45, 1, 0, 0x01),
        (0x06, 0, 0, 0x80000000),
        (0x06, 0, 0, 0x7FFF0000),
    ]
    assert _action_name(_simulate(jset, 3, 0)) == "ALLOW"  # 3 & 1
    # ja(무조건 점프) + ld imm + misc(tax/txa)
    misc = [
        (0x00, 0, 0, 7),
        (0x07, 0, 0, 0),
        (0x87, 0, 0, 0),
        (0x05, 0, 0, 0),
        (0x06, 0, 0, 0x7FFF0000),
    ]
    assert _action_name(_simulate(misc, 0, 0)) == "ALLOW"
    # 미지원 opcode(ALU) → None
    assert _simulate([(0x04, 0, 0, 0)], 0, 0) is None
    # 미지원 JMP op → None
    assert _simulate([(0x20, 0, 0, 0), (0x55, 0, 0, 0)], 0, 0) is None


def test_locate_and_decode_raw_blob():
    # arch-load k=0 변형 + 유효 프로그램을 잡아 디코딩한다.
    entries = [
        (0x20, 0, 0, 0),
        (0x15, 1, 0, 0xC000003E),
        (0x06, 0, 0, 0x80000000),
        (0x20, 0, 0, 0),
        (0x15, 1, 0, 59),
        (0x06, 0, 0, 0x7FFF0000),
        (0x06, 0, 0, 0x80000000),
    ]
    blob = b"".join(struct.pack("<HBBI", *e) for e in entries)
    located = _locate_filter(b"\x00" * 16 + blob + b"\xff" * 8)
    assert located is not None
    program, arch = located
    assert arch == 0xC000003E
    assert len(program) >= 5
    # 지원하지 않는 클래스(LDX=0x01)면 디코딩이 즉시 멈춘다.
    assert _decode(b"\x01\x00\x00\x00\x00\x00\x00\x00", 0) == []


def test_locate_filter_returns_none_without_signature():
    assert _locate_filter(b"no bpf filter here at all" * 4) is None


# --- 실 바이너리(gcc + 커널 헤더 필요) --------------------------------------


def test_blocklist_filter_detected(tmp_path):
    if not _headers_ok(tmp_path):
        pytest.skip("gcc + linux/seccomp.h 헤더 필요")
    report = analyze_seccomp(
        parse_elf(open(_compile(tmp_path, _BLOCKLIST_SRC, "bl"), "rb").read())
    )
    assert report.present is True
    assert report.arch == "AUDIT_ARCH_X86_64"
    assert report.default_action == "ALLOW"
    assert report.execve_blocked is True
    assert report.orw_available is True
    assert "execve" in report.blocked and "execveat" in report.blocked


def test_allowlist_filter_detected(tmp_path):
    if not _headers_ok(tmp_path):
        pytest.skip("gcc + linux/seccomp.h 헤더 필요")
    report = analyze_seccomp(
        parse_elf(open(_compile(tmp_path, _ALLOWLIST_SRC, "al"), "rb").read())
    )
    assert report.present is True
    assert report.default_action == "KILL_PROCESS"
    assert set(report.allowed) >= {"read", "write", "open", "openat"}
    assert report.execve_blocked is True
    assert report.orw_available is True


def test_no_seccomp_binary(tmp_path):
    if not (_SUPPORTED and _HAVE_GCC):
        pytest.skip("Linux/x86-64 + gcc 필요")
    report = analyze_seccomp(
        parse_elf(open(_compile(tmp_path, _PLAIN_SRC, "plain"), "rb").read())
    )
    assert report.present is False


def test_strategy_integration_blocks_execve_paths(tmp_path):
    if not _headers_ok(tmp_path):
        pytest.skip("gcc + linux/seccomp.h 헤더 필요")
    report = analyze_strategy(
        parse_elf(open(_compile(tmp_path, _BLOCKLIST_SRC, "st"), "rb").read())
    )
    assert report["seccomp"]["present"] is True
    assert report["seccomp"]["execve_blocked"] is True
    # execve/system 기반 경로는 seccomp 로 차단 처리돼야 한다.
    for path in report["paths"]:
        if path["id"] in {"ret2system", "execve"}:
            assert path["status"] == "blocked"
            assert any("seccomp" in b for b in path["blockers"])
    # ORW 안내가 limitations 에 포함돼야 한다.
    assert any("ORW" in x for x in report["limitations"])
