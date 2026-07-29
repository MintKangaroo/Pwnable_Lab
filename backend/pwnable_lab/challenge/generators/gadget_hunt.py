"""ROP Gadget — 특정 가젯(pop rdi; ret)의 주소를 찾는 문제."""

from __future__ import annotations

import random

from pwnable_lab.challenge.base import (
    ChallengeGenerator, POP_RDI_RET, POP_RSI_R15_RET, POP_RDX_RET,
    RET, XOR_EAX_RET, sub_rsp,
)
from pwnable_lab.challenge.models import ChallengeMeta, GeneratedChallenge
from pwnable_lab.elf.builder import ElfBuilder, Symbol
from pwnable_lab.analyzer.gadgets import find_gadgets, search_gadgets
from pwnable_lab.elf.parser import parse_elf


class GadgetHuntGenerator(ChallengeGenerator):
    meta = ChallengeMeta(
        slug="gadget-hunt",
        title="ROP Gadget",
        level="Medium",
        category="rop",
        technique="ROP 가젯 검색",
        description=(
            "NX 가 켜져 있어 셸코드를 직접 실행할 수 없습니다. ROP 체인을 짜려면 "
            "먼저 첫 번째 인자 레지스터를 제어할 'pop rdi ; ret' 가젯이 필요합니다. "
            "이 바이너리에서 해당 가젯의 주소를 찾으세요."
        ),
        prompt="'pop rdi ; ret' 가젯의 가상 주소를 16진수로 제출하세요.",
        answer_format="hex-address",
    )

    def generate(self, rng: random.Random) -> GeneratedChallenge:
        # 여러 가젯을 흩뿌리고 그중 하나가 pop rdi; ret
        chunks = [
            sub_rsp(0x18) + XOR_EAX_RET,
            POP_RSI_R15_RET,
            RET * rng.randint(1, 4),
            POP_RDX_RET,
            POP_RDI_RET,       # 목표 가젯
            POP_RSI_R15_RET,
        ]
        text = b"".join(chunks)

        image = ElfBuilder(
            text=text,
            rodata=b"/bin/sh\x00",
            symbols=[Symbol("main", ".text", 0, len(chunks[0]))],
            pie=False, nx=True, relro="partial", canary=False,
        )
        data = image.build()

        img = parse_elf(data)
        gadgets = find_gadgets(img)
        target = search_gadgets(gadgets, "pop rdi ; ret")
        # 정확히 'pop rdi ; ret' (2개 명령)만
        exact = [g for g in target if g.instructions == ["pop rdi", "ret"]]
        addr = exact[0].address

        return GeneratedChallenge(
            meta=self.meta,
            artifact=data,
            answer=hex(addr),
            solution=(
                "ROP 가젯 탭에서 'pop rdi ; ret' 로 검색하면 주소가 나옵니다. "
                "바이트로는 5f c3 입니다."
            ),
            hints=[
                "ROP 가젯 탭의 검색창에 'pop rdi' 를 입력하세요.",
                "가젯 바이트는 5f c3 (pop rdi = 0x5f, ret = 0xc3) 입니다.",
            ],
        )
