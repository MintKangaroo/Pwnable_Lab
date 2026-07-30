"""테스트용 ELF 합성 헬퍼."""

from __future__ import annotations

from pwnable_lab.challenge.base import POP_RDI_RET, RET, XOR_EAX_RET, sub_rsp
from pwnable_lab.elf.builder import ElfBuilder, Symbol


def sample_elf(**overrides) -> bytes:
    """가젯·심볼·문자열을 갖춘 대표 ELF 를 만든다."""
    text = sub_rsp(0x20) + POP_RDI_RET + RET + XOR_EAX_RET
    kwargs = dict(
        text=text,
        rodata=b"FLAG{test}\x00/bin/sh\x00",
        symbols=[
            Symbol("main", ".text", 0, len(text)),
            Symbol("win", ".text", len(sub_rsp(0x20)), 2),
            Symbol("gets", ".text", 0, 0),
        ],
        pie=False,
        nx=True,
        relro="partial",
        canary=False,
    )
    kwargs.update(overrides)
    return ElfBuilder(**kwargs).build()
