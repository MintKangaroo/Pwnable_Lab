"""문제 생성기 모음."""

from pwnable_lab.challenge.generators.checksec_audit import ChecksecAuditGenerator
from pwnable_lab.challenge.generators.format_flag import FormatFlagGenerator
from pwnable_lab.challenge.generators.gadget_hunt import GadgetHuntGenerator
from pwnable_lab.challenge.generators.offset_hunt import OffsetHuntGenerator
from pwnable_lab.challenge.generators.ret2win import Ret2WinGenerator
from pwnable_lab.challenge.generators.rop_chain import RopChainGenerator

ALL_GENERATORS = [
    Ret2WinGenerator(),
    OffsetHuntGenerator(),
    ChecksecAuditGenerator(),
    GadgetHuntGenerator(),
    FormatFlagGenerator(),
    RopChainGenerator(),
]

__all__ = ["ALL_GENERATORS"]
