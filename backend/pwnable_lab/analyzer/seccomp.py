"""seccomp-BPF 필터 정적 탐지·디코딩 — 허용/차단 syscall 판별.

현대 CTF pwn 은 흔히 ``prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)`` 로
seccomp-BPF 필터를 설치해 ``execve``/``execveat`` 를 막는다. 그러면 셸(execve/system)
전제가 깨지고 ORW(open-read-write)로 플래그를 읽어야 한다. 이 모듈은 바이너리를
**실행하지 않고** 필터 배열(``struct sock_filter[]``)을 찾아 BPF 프로그램을 디코딩·
시뮬레이션해 어떤 syscall 이 허용/차단되는지 판별한다(seccomp-tools 정적 덤프의 축약).

필터 배열은 아키텍처 검사 프롤로그(``ld [arch]``; ``jeq AUDIT_ARCH_*``)로 시작하므로
그 서명을 스캔해 위치를 잡는다. 각 엔트리는 8바이트 ``{u16 code, u8 jt, u8 jf, u32 k}``.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from pwnable_lab.elf.parser import ElfImage

# --- BPF opcode 상수 -------------------------------------------------------
_LD, _JMP, _RET, _ALU, _MISC = 0x00, 0x05, 0x06, 0x04, 0x07
_JA, _JEQ, _JGT, _JGE, _JSET = 0x00, 0x10, 0x20, 0x30, 0x40
_K, _X = 0x00, 0x08
_ABS = 0x20

# seccomp RET action 클래스.
_ACTIONS = {
    0x00000000: "KILL_THREAD",
    0x00030000: "TRAP",
    0x00050000: "ERRNO",
    0x7FC00000: "USER_NOTIF",
    0x7FF00000: "TRACE",
    0x7FFC0000: "LOG",
    0x7FFF0000: "ALLOW",
}
# 아키텍처 검사에 쓰이는 AUDIT_ARCH_* 값 → 이름.
_AUDIT_ARCH = {
    0xC000003E: "AUDIT_ARCH_X86_64",
    0x40000003: "AUDIT_ARCH_I386",
    0xC00000B7: "AUDIT_ARCH_AARCH64",
    0x40000028: "AUDIT_ARCH_ARM",
}
# 아치별 스캔할 syscall 번호 상한.
_MAX_NR = 470
# 필터로 인정할 최대 명령 수(방어적 상한).
_MAX_INSNS = 1024


@dataclass
class SeccompReport:
    present: bool
    arch: str | None = None
    instruction_count: int = 0
    default_action: str | None = None
    allowed: list[str] = field(default_factory=list)
    blocked: list[str] = field(default_factory=list)
    execve_blocked: bool = False
    orw_available: bool = False
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "present": self.present,
            "arch": self.arch,
            "instruction_count": self.instruction_count,
            "default_action": self.default_action,
            "allowed": self.allowed,
            "blocked": self.blocked,
            "execve_blocked": self.execve_blocked,
            "orw_available": self.orw_available,
            "notes": self.notes,
        }


def analyze_seccomp(image: ElfImage) -> SeccompReport:
    """바이너리에서 seccomp 필터를 찾아 허용/차단 syscall 을 판별한다."""

    located = _locate_filter(image.data)
    if located is None:
        return SeccompReport(present=False, notes=["seccomp 필터를 찾지 못함"])
    program, arch_val = located

    arch = _AUDIT_ARCH.get(arch_val, f"0x{arch_val:x}")
    # 기본 동작: 특수 처리되지 않을 높은 번호로 시뮬레이션.
    default_ret = _simulate(program, 0xFFFF, arch_val)
    default_action = _action_name(default_ret)

    allowed: list[str] = []
    blocked: list[str] = []
    for nr in range(_MAX_NR):
        ret = _simulate(program, nr, arch_val)
        if ret is None:
            continue
        action = _action_name(ret)
        name = _SYSCALLS.get(nr, f"syscall_{nr}")
        # 기본과 다른(명시적으로 지정된) syscall 만 목록에 담는다.
        if action != default_action:
            (allowed if action == "ALLOW" else blocked).append(name)

    def _allows(nr: int) -> bool:
        ret = _simulate(program, nr, arch_val)
        return ret is not None and _action_name(ret) == "ALLOW"

    execve_blocked = not _allows(59) and not _allows(322)  # execve, execveat
    orw = _allows(0) and _allows(1) and (_allows(2) or _allows(257))  # read/write/open

    notes: list[str] = []
    if execve_blocked:
        notes.append(
            "execve/execveat 가 차단됩니다 — 셸(execve/system) 대신 ORW"
            "(open→read→write) 로 플래그를 읽는 전략이 필요합니다."
        )
    if orw:
        notes.append("open/read/write 가 허용되어 ORW 전략이 가능합니다.")

    return SeccompReport(
        present=True,
        arch=arch,
        instruction_count=len(program),
        default_action=default_action,
        allowed=sorted(set(allowed)),
        blocked=sorted(set(blocked)),
        execve_blocked=execve_blocked,
        orw_available=orw,
        notes=notes,
    )


def _locate_filter(data: bytes) -> tuple[list[tuple[int, int, int, int]], int] | None:
    """아키텍처 검사 프롤로그로 필터 배열 위치를 잡아 디코딩한다.

    ``ld [W ABS], k∈{0(nr),4(arch)}`` 뒤에 ``jeq AUDIT_ARCH_*`` 가 오는 곳을 찾는다.
    반환: (BPF 명령 목록[(code,jt,jf,k)], 아키텍처 값). 못 찾으면 None.
    """

    # arch-load 서명: code=0x0020(LD|W|ABS), jt=jf=0, k∈{0,4}.
    for k_arch in (b"\x04\x00\x00\x00", b"\x00\x00\x00\x00"):
        sig = b"\x20\x00\x00\x00" + k_arch
        start = 0
        while True:
            idx = data.find(sig, start)
            if idx < 0:
                break
            start = idx + 1
            if idx + 16 > len(data):
                continue
            code2, jt2, jf2, k2 = struct.unpack_from("<HBBI", data, idx + 8)
            if code2 == (_JMP | _JEQ | _K) and k2 in _AUDIT_ARCH:
                program = _decode(data, idx)
                if program:
                    return program, k2
    return None


def _decode(data: bytes, off: int) -> list[tuple[int, int, int, int]]:
    """``off`` 부터 유효한 BPF 명령을 최대 상한까지 디코딩한다."""

    program: list[tuple[int, int, int, int]] = []
    pos = off
    while len(program) < _MAX_INSNS and pos + 8 <= len(data):
        code, jt, jf, k = struct.unpack_from("<HBBI", data, pos)
        cls = code & 0x07
        if cls not in (_LD, _JMP, _RET, _ALU, _MISC):
            break
        program.append((code, jt, jf, k))
        pos += 8
        if cls == _RET and jt == 0 and jf == 0:
            # RET 이후에도 배열은 이어질 수 있으나(다른 RET 분기), 유효 opcode 가
            # 아니면 위에서 멈춘다. 넉넉히 계속 디코딩한다.
            continue
    return program


def _simulate(
    program: list[tuple[int, int, int, int]], nr: int, arch_val: int
) -> int | None:
    """seccomp_data{nr, arch} 로 BPF 를 실행해 RET 값을 반환한다(무한루프 방어).

    seccomp 가 쓰는 부분집합만 구현: LD(W ABS/IMM), JMP(JA/JEQ/JGT/JGE/JSET, K/X),
    RET(K/A), ALU/MISC 일부. 미지원 명령을 만나면 None.
    """

    # seccomp_data: 0=nr, 4=arch, 8=IP(8B), 16..=args. 여기선 nr/arch 만 채운다.
    fields = {0: nr & 0xFFFFFFFF, 4: arch_val & 0xFFFFFFFF}
    acc = 0
    x = 0
    pc = 0
    steps = 0
    while pc < len(program) and steps < _MAX_INSNS * 4:
        steps += 1
        code, jt, jf, k = program[pc]
        cls = code & 0x07
        if cls == _RET:
            return acc if (code & 0x10) else k  # BPF_A→acc, BPF_K→k
        if cls == _LD:
            mode = code & 0xE0
            if mode == _ABS:
                acc = fields.get(k, 0)
            elif mode == 0x00:  # IMM
                acc = k
            else:
                return None
            pc += 1
            continue
        if cls == _JMP:
            op = code & 0xF0
            src = code & 0x08
            cmp = x if src == _X else k
            if op == _JA:
                pc += 1 + k
                continue
            if op == _JEQ:
                taken = acc == cmp
            elif op == _JGT:
                taken = acc > cmp
            elif op == _JGE:
                taken = acc >= cmp
            elif op == _JSET:
                taken = bool(acc & cmp)
            else:
                return None
            pc += 1 + (jt if taken else jf)
            continue
        if cls == _MISC:
            # TAX(0x00)/TXA(0x80).
            if code & 0x80:
                acc = x
            else:
                x = acc
            pc += 1
            continue
        # ALU 등 미지원.
        return None
    return None


def _action_name(ret: int | None) -> str:
    if ret is None:
        return "UNKNOWN"
    if ret & 0x80000000:
        return "KILL_PROCESS"
    return _ACTIONS.get(ret & 0x7FFF0000, f"0x{ret & 0xFFFF0000:08x}")


# x86-64 syscall 번호 → 이름(pwn 관련 위주의 축약 표).
_SYSCALLS = {
    0: "read", 1: "write", 2: "open", 3: "close", 4: "stat", 5: "fstat",
    8: "lseek", 9: "mmap", 10: "mprotect", 11: "munmap", 12: "brk",
    16: "ioctl", 21: "access", 22: "pipe", 32: "dup", 33: "dup2",
    39: "getpid", 41: "socket", 42: "connect", 43: "accept", 44: "sendto",
    45: "recvfrom", 49: "bind", 50: "listen", 56: "clone", 57: "fork",
    58: "vfork", 59: "execve", 60: "exit", 62: "kill", 78: "getdents",
    83: "mkdir", 87: "unlink", 89: "readlink", 96: "gettimeofday",
    101: "ptrace", 102: "getuid", 105: "setuid", 157: "prctl",
    158: "arch_prctl", 165: "mount", 200: "tkill", 201: "time",
    202: "futex", 217: "getdents64", 231: "exit_group", 257: "openat",
    259: "readlinkat", 262: "newfstatat", 267: "readlinkat2",
    280: "utimensat", 288: "accept4", 302: "prlimit64", 317: "seccomp",
    318: "getrandom", 322: "execveat", 332: "statx",
}  # fmt: skip


__all__ = ["SeccompReport", "analyze_seccomp"]
