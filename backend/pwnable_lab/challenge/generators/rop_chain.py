"""ROP Chain — 다단계 분석: 가젯 + 심볼 + XOR 인코딩된 인자 복원(Hard)."""

from __future__ import annotations

import random

from pwnable_lab.challenge.base import (
    POP_RDI_RET,
    POP_RSI_R15_RET,
    RET,
    XOR_EAX_RET,
    ChallengeGenerator,
    sub_rsp,
)
from pwnable_lab.challenge.models import ChallengeMeta, GeneratedChallenge
from pwnable_lab.elf.builder import ElfBuilder, Symbol

_COMMANDS = ["/bin/sh", "/bin/cat flag", "cat /etc/passwd", "/bin/dash -i"]


class RopChainGenerator(ChallengeGenerator):
    meta = ChallengeMeta(
        slug="rop-chain",
        title="ROP Chain Reconstruction",
        level="Hard",
        category="rop",
        technique="가젯 + 심볼 + XOR 다단계 분석",
        description=(
            "system() 을 호출하는 ROP 체인을 완성하려 합니다. system 의 인자로 넘길 "
            "명령 문자열이 .rodata 에 단일 바이트 XOR 로 인코딩되어 숨겨져 있고, XOR "
            "키는 별도 마커 문자열 'key=0xNN' 로 남아 있습니다. 'pop rdi ; ret' 가젯과 "
            "system 심볼, 그리고 디코딩된 명령 문자열까지 모두 찾아야 체인이 완성됩니다. "
            "최종적으로 복원한 명령 문자열을 제출하세요."
        ),
        prompt="XOR 디코딩으로 복원한 명령 문자열 전체를 제출하세요. (예: /bin/sh)",
        answer_format="text",
    )

    def generate(self, rng: random.Random) -> GeneratedChallenge:
        command = rng.choice(_COMMANDS)
        key = rng.randint(1, 0xFF)
        encoded = bytes(b ^ key for b in command.encode())

        rodata = (
            b"ROP chain target: system()\x00"
            + f"key=0x{key:02x}\x00".encode()
            + b"payload:\x00"
            + encoded
            + b"\x00"
            + b"end\x00"
        )
        # pop rdi; ret 가젯과 system 심볼 배치
        code = sub_rsp(0x20) + POP_RDI_RET + POP_RSI_R15_RET + RET + XOR_EAX_RET
        image = ElfBuilder(
            text=code,
            rodata=rodata,
            symbols=[
                Symbol("main", ".text", 0, len(code)),
                Symbol("system", ".text", 0, 0),  # 외부 함수 표식
            ],
            pie=False,
            nx=True,
            relro="partial",
            canary=True,
        )
        data = image.build()

        return GeneratedChallenge(
            meta=self.meta,
            artifact=data,
            answer=command,
            solution=(
                f"1) 문자열 탭에서 'key=0x{key:02x}' 를 찾아 XOR 키를 얻습니다. "
                f"2) 그 뒤 'payload:' 다음의 인코딩된 바이트를 헥스 뷰어로 읽습니다. "
                f"3) 각 바이트를 0x{key:02x} 로 XOR 하면 '{command}' 가 복원됩니다. "
                f"4) 'pop rdi ; ret' 가젯으로 이 문자열 주소를 rdi 에 넣고 system 을 호출."
            ),
            hints=[
                "문자열 탭에서 'key=0x..' 마커를 찾아 XOR 키를 얻으세요.",
                "헥스 뷰어에서 'payload:' 뒤의 인코딩된 바이트를 읽으세요.",
                "각 바이트를 키로 XOR 하면 명령 문자열이 됩니다.",
            ],
        )
