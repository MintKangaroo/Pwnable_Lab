"""De Bruijn 순환 패턴 생성 및 오프셋 탐색.

스택 오버플로우에서 반환 주소를 덮는 데 필요한 정확한 패딩 길이를 찾을 때 사용한다.
pwntools 의 ``cyclic`` / ``cyclic_find`` 와 동일한 알고리즘(기본 알파벳, subseq=4).
"""

from __future__ import annotations

import struct

_DEFAULT_ALPHABET = b"abcdefghijklmnopqrstuvwxyz"


def de_bruijn(alphabet: bytes = _DEFAULT_ALPHABET, n: int = 4):
    """De Bruijn 수열 B(k, n) 을 생성하는 제너레이터(무한 아님, 주기 k**n)."""
    k = len(alphabet)
    a = [0] * (k * n)
    sequence: list[int] = []

    def db(t: int, p: int) -> None:
        if t > n:
            if n % p == 0:
                sequence.extend(a[1 : p + 1])
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                db(t + 1, t)

    db(1, 1)
    for i in sequence:
        yield alphabet[i]


def cyclic(length: int, *, alphabet: bytes = _DEFAULT_ALPHABET, n: int = 4) -> bytes:
    """길이 ``length`` 의 순환 패턴을 반환한다."""
    if length < 0:
        raise ValueError("length 는 음수일 수 없습니다.")
    if length > len(alphabet) ** n:
        raise ValueError(
            f"length {length} 가 최대 주기 {len(alphabet) ** n} 를 초과합니다."
        )
    gen = de_bruijn(alphabet, n)
    return bytes(next(gen) for _ in range(length))


def cyclic_find(subseq: bytes | int, *, alphabet: bytes = _DEFAULT_ALPHABET,
                n: int = 4, max_length: int = 65536) -> int:
    """부분 수열(또는 4바이트 레지스터 값)이 처음 등장하는 오프셋을 반환.

    ``subseq`` 가 int 이면 리틀엔디언 4바이트로 변환해 검색한다(EIP/RSP 값 대응).
    찾지 못하면 -1.
    """
    if isinstance(subseq, int):
        subseq = struct.pack("<I", subseq & 0xFFFFFFFF)
    if len(subseq) < n:
        raise ValueError(f"부분 수열은 최소 {n} 바이트여야 합니다.")
    needle = subseq[:n]
    # n=8이면 전체 주기가 26**8 이므로 현실적으로 만들 수 없다. 애플리케이션이
    # 허용하는 패턴 길이까지만 검색해 CPU/메모리 고갈을 막는다.
    full = cyclic(min(len(alphabet) ** n, max_length), alphabet=alphabet, n=n)
    idx = full.find(needle)
    return idx
