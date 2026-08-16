"""실행 환경의 libc 심볼 오프셋 해석 — 2단계 ret2libc 의 libc 측 재료.

leak 으로 얻은 런타임 ``puts`` 주소에서 libc base 를 계산하려면 **대상이 실제로
로드하는 libc** 의 심볼 오프셋이 필요하다. in-process 실행에서는 이 프로세스가
쓰는 libc 와 동일하므로 ``/proc/self/maps`` 에서 그 파일을 찾아 파싱한다.

.. note::
   컨테이너(``sandbox_executor="container"``)에서는 libc 가 다르므로 이 해석은
   컨테이너 **안에서** 수행돼야 한다. 현재 2단계 러너는 콜백 기반이라 컨테이너
   CLI 로 노출돼 있지 않고, 완전 자동 ret2libc 는 in-process 경로 전용이다.
"""

from __future__ import annotations

import re
from pathlib import Path

from pwnable_lab.analyzer.strategy import find_binsh
from pwnable_lab.elf.parser import parse_elf

_LIBC_MAPS = re.compile(r"(/\S*/libc\.so[.0-9]*)")


def system_libc_path() -> str | None:
    """현재 프로세스가 로드한 libc.so 의 절대 경로(없으면 None)."""

    try:
        with open("/proc/self/maps") as fh:
            for line in fh:
                match = _LIBC_MAPS.search(line)
                if match and Path(match.group(1)).is_file():
                    return match.group(1)
    except OSError:
        pass
    return None


def resolve_libc_symbols(path: str | None = None) -> dict | None:
    """libc 의 ``{"path","puts","system","binsh"}`` 오프셋을 해석(없으면 None)."""

    path = path or system_libc_path()
    if not path:
        return None
    try:
        image = parse_elf(Path(path).read_bytes())
    except OSError:
        return None
    symbols = {
        sym.name: sym.addr
        for sym in image.dynamic_symbols
        if sym.defined and sym.addr and sym.name
    }
    binsh = find_binsh(image)
    if "puts" not in symbols or "system" not in symbols or binsh is None:
        return None
    return {
        "path": path,
        "puts": symbols["puts"],
        "system": symbols["system"],
        "binsh": binsh,
    }
