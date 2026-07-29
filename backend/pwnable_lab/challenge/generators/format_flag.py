"""Format String — 포맷 스트링 유출로 드러나는 숨겨진 플래그를 찾는 문제."""

from __future__ import annotations

import random

from pwnable_lab.challenge.base import ChallengeGenerator, XOR_EAX_RET, sub_rsp
from pwnable_lab.challenge.models import ChallengeMeta, GeneratedChallenge
from pwnable_lab.elf.builder import ElfBuilder, Symbol

_WORDS = ["stack", "canary", "pivot", "gadget", "leak", "rop", "shell", "pwn"]


class FormatFlagGenerator(ChallengeGenerator):
    meta = ChallengeMeta(
        slug="format-flag",
        title="Format String Leak",
        level="Medium",
        category="format-string",
        technique="문자열 추출 · printf 취약점",
        description=(
            "printf(user_input) 처럼 포맷 스트링이 사용자 제어 하에 있습니다. "
            "%s/%p 로 .rodata 에 저장된 비밀 플래그를 그대로 읽어낼 수 있습니다. "
            "정적 분석으로 그 플래그 문자열을 찾으세요."
        ),
        prompt="바이너리에 숨겨진 플래그 문자열 전체를 제출하세요. (예: FLAG{...})",
        answer_format="text",
    )

    def generate(self, rng: random.Random) -> GeneratedChallenge:
        secret = "_".join(rng.sample(_WORDS, 3))
        flag = f"FLAG{{{secret}}}"
        # 플래그를 다른 문자열들 사이에 숨긴다
        rodata = (
            b"Enter your name: \x00"
            b"%s\x00"
            + b"Hello, \x00"
            + flag.encode() + b"\x00"
            + b"Goodbye\x00"
        )
        code = sub_rsp(0x28) + XOR_EAX_RET

        image = ElfBuilder(
            text=code,
            rodata=rodata,
            symbols=[
                Symbol("main", ".text", 0, len(code)),
                Symbol("printf", ".text", 0, 0),  # 임포트 표식
            ],
            pie=False, nx=True, relro="partial", canary=True,
        )
        data = image.build()

        return GeneratedChallenge(
            meta=self.meta,
            artifact=data,
            answer=flag,
            solution=(
                f"문자열 추출 탭에서 .rodata 의 ASCII 문자열을 나열하면 "
                f"{flag} 를 찾을 수 있습니다."
            ),
            hints=[
                "문자열(strings) 탭을 열어 .rodata 영역을 확인하세요.",
                "FLAG{ 로 시작하는 문자열을 찾으세요.",
            ],
        )
