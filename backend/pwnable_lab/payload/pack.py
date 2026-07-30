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


def hexdump_payload(payload: bytes, width: int = 16) -> str:
    """페이로드를 사람이 읽을 수 있는 헥스덤프 문자열로."""
    lines = []
    for off in range(0, len(payload), width):
        chunk = payload[off : off + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        asciipart = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        lines.append(f"{off:08x}  {hexpart:<{width * 3}}  {asciipart}")
    return "\n".join(lines)
