"""QEMU user-mode 실행 — 다른 아키텍처 바이너리 실행 (Phase 6D).

네이티브 ptrace 러너(:mod:`sandbox.runner`)는 x86-64 전용이다. CTF/실전 바이너리는
ARM·MIPS·RISC-V 등 다른 아키텍처인 경우가 많은데, 이 모듈은 ``qemu-<arch>-static``
(user-mode)로 그런 바이너리를 실행해 stdout·종료코드를 관측한다. 로드맵의
"QEMU/rr/reconstruction assistance" 중 크로스아키텍처 실행 조각이다.

.. warning::
   신뢰할 수 없는 바이너리를 **실행**한다(qemu user-mode). 자원 상한(rlimit)·프로세스
   그룹 종료·wall-clock 타임아웃만 강제하므로, 프로덕션에서는 network-disabled 일회용
   컨테이너 경계 안에서만 호출해야 한다(서비스 계층이 게이트를 강제). qemu 는 자체적
   으로 네트워크를 막지 않는다 — 격리 경계가 그 역할을 한다.
"""

from __future__ import annotations

import os
import resource
import shutil
import signal
import subprocess

from pwnable_lab.errors import SandboxError
from pwnable_lab.sandbox.runner import SandboxLimits

# ELF e_machine(숫자) → qemu-user 아키텍처 접미사.
_EM_TO_ARCH = {
    0x03: "i386",
    0x28: "arm",
    0x3E: "x86_64",
    0x08: "mips",
    0x14: "ppc",
    0x15: "ppc64",
    0xB7: "aarch64",
    0xF3: "riscv64",
    0x16: "s390x",
}


def qemu_arch(data: bytes) -> str | None:
    """ELF 헤더 e_machine 에서 qemu-user 아키텍처 접미사를 유추한다(없으면 None)."""

    if len(data) < 20 or data[:4] != b"\x7fELF":
        return None
    little = data[5] != 2  # EI_DATA: 2 == big-endian
    e_machine = int.from_bytes(data[18:20], "little" if little else "big")
    return _EM_TO_ARCH.get(e_machine)


def locate_qemu(arch: str) -> str | None:
    """``qemu-<arch>-static`` 또는 ``qemu-<arch>`` 실행 파일 경로(PATH). 없으면 None."""

    return shutil.which(f"qemu-{arch}-static") or shutil.which(f"qemu-{arch}")


def run_under_qemu(
    binary_path: str,
    *,
    stdin_data: bytes = b"",
    limits: SandboxLimits | None = None,
) -> dict:
    """대상 바이너리를 아키텍처에 맞는 qemu-user 로 실행하고 결과를 관측한다.

    자원 상한(CPU/주소공간)·프로세스그룹·wall-clock 타임아웃으로 감싼다. 반환은
    아키텍처·사용한 qemu·종료코드/시그널·타임아웃 여부·stdout(텍스트+hex)이다.
    """

    limits = limits or SandboxLimits()
    limits.validate()
    if not os.path.isfile(binary_path):
        raise SandboxError(f"실행 대상 파일이 없습니다: {binary_path}")

    with open(binary_path, "rb") as fh:
        head = fh.read(64)
    arch = qemu_arch(head)
    if arch is None:
        return {"attempted": False, "reason": "unknown-arch"}
    qemu = locate_qemu(arch)
    if qemu is None:
        return {"attempted": False, "reason": f"qemu-{arch}-unavailable", "arch": arch}

    def _preexec() -> None:  # pragma: no cover - 자식 프로세스
        os.setsid()
        cpu = limits.cpu_seconds
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
        space = limits.address_space_bytes
        resource.setrlimit(resource.RLIMIT_AS, (space, space))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    proc = subprocess.Popen(
        [qemu, binary_path],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        preexec_fn=_preexec,
    )
    timed_out = False
    try:
        out, _ = proc.communicate(input=stdin_data, timeout=limits.wall_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()
        out, _ = proc.communicate()

    out = out or b""
    cap = limits.capture_stdout_bytes
    truncated = len(out) > cap
    out = out[:cap]
    rc = proc.returncode
    exit_code = rc if rc is not None and rc >= 0 else None
    term_signal = -rc if rc is not None and rc < 0 else None
    return {
        "attempted": True,
        "arch": arch,
        "qemu": os.path.basename(qemu),
        "timed_out": timed_out,
        "exit_code": exit_code,
        "signal": term_signal,
        "signal_name": (signal.Signals(term_signal).name if term_signal else None),
        "truncated": truncated,
        "stdout": out.decode("utf-8", "replace"),
        "stdout_hex": out.hex(),
    }


__all__ = ["locate_qemu", "qemu_arch", "run_under_qemu"]
