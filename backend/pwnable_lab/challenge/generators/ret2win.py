"""Ret2Win — 숨겨진 win 함수의 주소를 찾는 가장 기본적인 문제."""

from __future__ import annotations

import random

from pwnable_lab.challenge.base import (
    ChallengeGenerator, RET, XOR_EAX_RET, sub_rsp,
)
from pwnable_lab.challenge.models import ChallengeMeta, GeneratedChallenge
from pwnable_lab.elf.builder import ElfBuilder, Symbol
from pwnable_lab.elf.parser import parse_elf


class Ret2WinGenerator(ChallengeGenerator):
    meta = ChallengeMeta(
        slug="ret2win",
        title="Ret2Win",
        level="Easy",
        category="stack",
        technique="심볼 테이블 분석",
        description=(
            "이 바이너리에는 절대 호출되지 않는 win() 함수가 숨어 있습니다. "
            "스택 버퍼 오버플로우로 반환 주소를 win() 으로 덮으면 플래그를 얻습니다."
        ),
        prompt="win() 함수의 가상 주소를 16진수로 제출하세요. (예: 0x401156)",
        answer_format="hex-address",
    )

    def generate(self, rng: random.Random) -> GeneratedChallenge:
        # main: 스택 프레임 확보 후 종료. win: 별도 위치.
        main_code = sub_rsp(0x20) + XOR_EAX_RET
        pad = RET * rng.randint(3, 12)
        win_code = sub_rsp(0x10) + XOR_EAX_RET  # win()

        text = main_code + pad + win_code
        win_off = len(main_code) + len(pad)

        image = ElfBuilder(
            text=text,
            rodata=b"flag: overwrite return address to win\x00",
            symbols=[
                Symbol("main", ".text", 0, len(main_code)),
                Symbol("win", ".text", win_off, len(win_code)),
            ],
            pie=False, nx=True, relro="partial", canary=False,
        )
        data = image.build()
        win_addr = parse_elf(data).symbol("win").addr

        return GeneratedChallenge(
            meta=self.meta,
            artifact=data,
            answer=hex(win_addr),
            solution=(
                "심볼 탭에서 win 심볼의 st_value 를 읽으면 됩니다. "
                "checksec 상 No PIE 이므로 주소는 고정입니다."
            ),
            hints=[
                "checksec 결과 PIE 가 비활성(No PIE)인지 확인하세요 — 주소가 고정입니다.",
                "심볼 분석 탭에서 win 을 검색하세요.",
            ],
        )
