"""Stack Offset — 스택 프레임 크기로부터 반환주소까지의 패딩 오프셋을 계산."""

from __future__ import annotations

import random

from pwnable_lab.challenge.base import ChallengeGenerator, XOR_EAX_RET, sub_rsp
from pwnable_lab.challenge.models import ChallengeMeta, GeneratedChallenge
from pwnable_lab.elf.builder import ElfBuilder, Symbol


class OffsetHuntGenerator(ChallengeGenerator):
    meta = ChallengeMeta(
        slug="offset-hunt",
        title="Stack Offset",
        level="Easy",
        category="stack",
        technique="디스어셈블 · cyclic 오프셋",
        description=(
            "vulnerable() 은 스택에 지역 버퍼를 잡고 gets() 로 입력을 받습니다. "
            "디스어셈블로 스택 프레임 크기를 확인해, 저장된 rbp 를 지나 반환 주소를 "
            "덮는 데 필요한 정확한 패딩 바이트 수를 구하세요."
        ),
        prompt=(
            "반환 주소를 덮기 위한 패딩 바이트 수(정수)를 제출하세요. "
            "(버퍼 크기 + 저장된 rbp 8바이트)"
        ),
        answer_format="integer",
    )

    def generate(self, rng: random.Random) -> GeneratedChallenge:
        # 프레임 크기: 16의 배수, 0x20~0x70
        frame = rng.choice([0x20, 0x30, 0x40, 0x50, 0x60, 0x70])
        # vulnerable(): push rbp; mov rbp,rsp; sub rsp, frame; ... ; ret
        prologue = b"\x55\x48\x89\xe5"  # push rbp; mov rbp, rsp
        code = prologue + sub_rsp(frame) + XOR_EAX_RET
        text = code

        image = ElfBuilder(
            text=text,
            rodata=b"input: ",
            symbols=[Symbol("vulnerable", ".text", 0, len(code))],
            pie=False, nx=True, relro="partial", canary=False,
        )
        data = image.build()

        # 버퍼는 rbp - frame 에서 시작한다고 가정 → 패딩 = frame + 8(saved rbp)
        offset = frame + 8

        return GeneratedChallenge(
            meta=self.meta,
            artifact=data,
            answer=str(offset),
            solution=(
                f"디스어셈블에서 'sub rsp, {hex(frame)}' 를 확인합니다. 버퍼가 프레임 "
                f"바닥에 있으므로 저장된 rbp(8바이트)까지 더해 오프셋은 "
                f"{frame} + 8 = {offset} 입니다."
            ),
            hints=[
                "디스어셈블 탭에서 vulnerable 의 프롤로그(sub rsp, X)를 찾으세요.",
                "패딩 = 프레임 크기 + 저장된 rbp(8) 입니다.",
                "cyclic 패턴 생성기로 실제 오프셋을 검증할 수 있습니다.",
            ],
        )
