"""문자열 추출 — ASCII 및 UTF-16LE."""

from __future__ import annotations

from dataclasses import dataclass

_PRINTABLE = set(range(0x20, 0x7F))


@dataclass
class ExtractedString:
    offset: int
    encoding: str  # "ascii" | "utf-16le"
    value: str


def extract_strings(
    data: bytes, *, min_length: int = 4, max_strings: int = 20000
) -> list[ExtractedString]:
    out: list[ExtractedString] = []
    out.extend(_ascii_strings(data, min_length))
    out.extend(_utf16_strings(data, min_length))
    out.sort(key=lambda s: s.offset)
    return out[:max_strings]


def _ascii_strings(data: bytes, min_length: int) -> list[ExtractedString]:
    out: list[ExtractedString] = []
    start = None
    for i, b in enumerate(data):
        if b in _PRINTABLE:
            if start is None:
                start = i
        else:
            if start is not None and i - start >= min_length:
                out.append(
                    ExtractedString(start, "ascii", data[start:i].decode("ascii"))
                )
            start = None
    if start is not None and len(data) - start >= min_length:
        out.append(ExtractedString(start, "ascii", data[start:].decode("ascii")))
    return out


def _utf16_strings(data: bytes, min_length: int) -> list[ExtractedString]:
    out: list[ExtractedString] = []
    i = 0
    n = len(data)
    while i + 1 < n:
        if data[i] in _PRINTABLE and data[i + 1] == 0:
            start = i
            chars = []
            while i + 1 < n and data[i] in _PRINTABLE and data[i + 1] == 0:
                chars.append(chr(data[i]))
                i += 2
            if len(chars) >= min_length:
                out.append(ExtractedString(start, "utf-16le", "".join(chars)))
        else:
            i += 1
    return out
