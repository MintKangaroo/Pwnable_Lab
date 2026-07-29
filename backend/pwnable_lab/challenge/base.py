"""문제 생성기 추상 베이스 및 공용 헬퍼."""

from __future__ import annotations

import random
from abc import ABC, abstractmethod

from pwnable_lab.challenge.models import ChallengeMeta, GeneratedChallenge


class ChallengeGenerator(ABC):
    """모든 문제 생성기의 베이스.

    생성기는 시드로 결정론적 아티팩트를 만든다. 같은 슬러그는 항상 같은 시드를
    쓰므로, 서버 재시작 후에도 다운로드 아티팩트와 정답이 안정적이다.
    """

    meta: ChallengeMeta

    @abstractmethod
    def generate(self, rng: random.Random) -> GeneratedChallenge:
        """시드된 RNG 로 문제 인스턴스를 생성한다."""

    def build(self) -> GeneratedChallenge:
        seed = _slug_seed(self.meta.slug)
        return self.generate(random.Random(seed))


def _slug_seed(slug: str) -> int:
    return int.from_bytes(slug.encode(), "little") % (2**32)


# x86-64 짧은 코드 조각 (디스어셈블 가능하고 유효한 명령들)
NOP = b"\x90"
RET = b"\xc3"
POP_RDI_RET = b"\x5f\xc3"
POP_RSI_R15_RET = b"\x5e\x41\x5f\xc3"
POP_RDX_RET = b"\x5a\xc3"
XOR_EAX_RET = b"\x31\xc0\xc3"


def sub_rsp(size: int) -> bytes:
    """``sub rsp, imm8/imm32`` 를 인코딩한다(스택 프레임 크기 표현용)."""
    if 0 <= size < 0x80:
        return b"\x48\x83\xec" + bytes([size])  # sub rsp, imm8
    return b"\x48\x81\xec" + size.to_bytes(4, "little")  # sub rsp, imm32
