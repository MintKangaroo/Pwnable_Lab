"""Format-neutral Shannon entropy analysis with bounded region output."""

from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    size = len(data)
    return -sum(
        (count / size) * math.log2(count / size) for count in Counter(data).values()
    )


def raw_entropy_windows(
    data: bytes, *, window_size: int = 65_536, max_windows: int = 512
) -> list[dict]:
    if not data:
        return []
    if len(data) > window_size * max_windows:
        window_size = math.ceil(len(data) / max_windows)
    return [
        {
            "name": f"raw:{offset:#x}",
            "offset": offset,
            "size": len(chunk),
            "entropy": round(shannon_entropy(chunk), 4),
            "executable": None,
            "writable": None,
            "verification": "unknown",
        }
        for offset in range(0, len(data), window_size)
        if (chunk := data[offset : offset + window_size])
    ]
