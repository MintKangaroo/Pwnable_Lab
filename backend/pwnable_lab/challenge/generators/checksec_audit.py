"""Checksec Audit — 비활성화된 완화 기법을 찾아내는 문제."""

from __future__ import annotations

import random

from pwnable_lab.challenge.base import XOR_EAX_RET, ChallengeGenerator, sub_rsp
from pwnable_lab.challenge.models import ChallengeMeta, GeneratedChallenge
from pwnable_lab.elf.builder import ElfBuilder, Symbol

# 정답 키워드 -> 설명
_WEAKNESS = {
    "nx": "GNU_STACK 세그먼트가 실행 가능(RWX)이라 스택에서 셸코드 실행이 가능합니다.",
    "canary": "__stack_chk_fail 심볼이 없어 스택 카나리가 적용되지 않았습니다.",
    "pie": "ET_EXEC(No PIE)라 코드/데이터 주소가 고정입니다.",
    "relro": "GNU_RELRO 세그먼트가 없어 GOT 덮어쓰기가 가능합니다.",
}


class ChecksecAuditGenerator(ChallengeGenerator):
    meta = ChallengeMeta(
        slug="checksec-audit",
        title="Checksec Audit",
        level="Easy",
        category="mitigation",
        technique="완화 기법 점검",
        description=(
            "이 바이너리는 대부분의 보호 기법이 켜져 있지만 딱 하나가 비활성화되어 "
            "있습니다. checksec 결과를 보고 공격자에게 열려 있는 그 한 가지를 지목하세요."
        ),
        prompt="비활성화된 완화 기법의 키워드를 제출하세요: nx, canary, pie, relro 중 하나",
        answer_format="keyword",
    )

    def generate(self, rng: random.Random) -> GeneratedChallenge:
        weakness = rng.choice(list(_WEAKNESS))
        code = sub_rsp(0x20) + XOR_EAX_RET

        nx = True
        pie = True
        relro = "full"
        canary = True
        if weakness == "nx":
            nx = False
        elif weakness == "pie":
            pie = False
        elif weakness == "relro":
            relro = "none"
        elif weakness == "canary":
            canary = False

        image = ElfBuilder(
            text=code,
            rodata=b"audit me\x00",
            symbols=[Symbol("main", ".text", 0, len(code))],
            nx=nx,
            pie=pie,
            relro=relro,
            canary=canary,
        )
        data = image.build()

        return GeneratedChallenge(
            meta=self.meta,
            artifact=data,
            answer=weakness,
            solution=_WEAKNESS[weakness],
            hints=[
                "checksec 탭의 6개 항목을 하나씩 확인하세요.",
                "나머지는 모두 켜져 있고 정확히 하나만 꺼져 있습니다.",
            ],
        )
