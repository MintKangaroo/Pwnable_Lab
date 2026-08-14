"""Bounded, evidence-based x86/x86-64 ROP gadget analysis.

The scanner only decodes file-backed executable ELF sections. Exact bytes and
instruction effects are verified with Capstone; the quality score and chain
simulation are explicitly heuristic/inferred. Uploaded artifacts are never run.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field, replace
from itertools import chain, islice
from typing import Literal, cast

from capstone import (  # type: ignore[import-untyped]
    CS_AC_READ,
    CS_AC_WRITE,
    CS_ARCH_X86,
    CS_GRP_CALL,
    CS_GRP_JUMP,
    CS_GRP_RET,
    CS_MODE_32,
    CS_MODE_64,
    Cs,
)
from capstone.x86_const import (  # type: ignore[import-untyped]
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
)

from pwnable_lab.elf.parser import ElfImage
from pwnable_lab.errors import AnalysisError

_MAX_BACK = 40
_STACK_REGISTERS = {"rsp", "esp", "sp"}
_SAFE_REGEX_META = re.compile(r"^[A-Za-z0-9_\s;,.+*?^$|\[\]\\:-]+$")


@dataclass
class Gadget:
    address: int
    bytes_hex: str
    instructions: list[str]
    section: str
    terminator: str
    stack_change: int | None
    stack_words: int | None
    registers_read: list[str]
    registers_written: list[str]
    popped_registers: list[str]
    memory_read: bool
    memory_write: bool
    categories: list[str]
    side_effect_count: int
    quality_score: float
    pie_offset: int | None
    position_independent: bool
    bad_bytes: list[str] = field(default_factory=list)
    verification: str = "verified"
    confidence: float = 1.0
    evidence: list[str] = field(default_factory=list)

    @property
    def text(self) -> str:
        return " ; ".join(self.instructions)

    def as_dict(self) -> dict:
        result = asdict(self)
        result["text"] = self.text
        return result


@dataclass(frozen=True)
class GadgetScanResult:
    gadgets: list[Gadget]
    truncated: bool
    executable_sections: int
    position_independent: bool
    image_base: int


@dataclass(frozen=True)
class GadgetFilter:
    query: str = ""
    regex: bool = False
    register: str | None = None
    category: str | None = None
    min_stack_change: int | None = None
    max_stack_change: int | None = None
    bad_bytes: tuple[int, ...] = ()
    address_min: int | None = None
    address_max: int | None = None
    sort: str = "quality"
    order: str = "desc"


def _make_cs(image: ElfImage) -> Cs:
    if image.machine not in {"EM_386", "EM_X86_64"}:
        raise AnalysisError(
            f"ROP gadget search supports x86/x86-64 ELF only: {image.machine}"
        )
    mode = CS_MODE_64 if image.bits == 64 else CS_MODE_32
    engine = Cs(CS_ARCH_X86, mode)
    engine.detail = True
    return engine


def scan_gadgets(
    image: ElfImage, *, max_gadgets: int = 2000, max_depth: int = 5
) -> GadgetScanResult:
    """Scan short, exactly decoded gadgets from executable sections."""

    engine = _make_cs(image)
    seen: dict[int, Gadget] = {}
    image_base = _image_base(image)
    executable_sections = 0

    for section in image.sections:
        if not section.executable or section.size == 0:
            continue
        executable_sections += 1
        blob = image.data[section.offset : section.offset + section.size]
        terminals = chain(_terminal_ranges(blob), _indirect_terminals(engine, blob))
        for terminal_start, terminal_end in terminals:
            for start in range(max(0, terminal_start - _MAX_BACK), terminal_start + 1):
                gadget = _decode_gadget(
                    engine,
                    blob,
                    start,
                    terminal_end,
                    section.addr,
                    section.name,
                    image,
                    image_base,
                    max_depth,
                )
                if gadget and gadget.address not in seen:
                    seen[gadget.address] = gadget
                    if len(seen) >= max_gadgets:
                        return GadgetScanResult(
                            gadgets=_sorted(seen),
                            truncated=True,
                            executable_sections=executable_sections,
                            position_independent=image.e_type == "ET_DYN",
                            image_base=image_base,
                        )
    return GadgetScanResult(
        gadgets=_sorted(seen),
        truncated=False,
        executable_sections=executable_sections,
        position_independent=image.e_type == "ET_DYN",
        image_base=image_base,
    )


def find_gadgets(
    image: ElfImage, *, max_gadgets: int = 2000, max_depth: int = 5
) -> list[Gadget]:
    """Compatibility wrapper returning only the scanned gadget list."""

    return scan_gadgets(image, max_gadgets=max_gadgets, max_depth=max_depth).gadgets


def filter_gadgets(
    gadgets: list[Gadget],
    filters: GadgetFilter,
    *,
    bits: int,
    endian: str,
) -> list[Gadget]:
    """Apply bounded search and semantic filters without modifying scan evidence."""

    matcher = _query_matcher(filters.query, filters.regex)
    register = filters.register.lower().strip() if filters.register else None
    category = filters.category.lower().strip() if filters.category else None
    width = bits // 8
    byteorder = cast(Literal["little", "big"], endian)
    output: list[Gadget] = []
    for gadget in gadgets:
        if matcher and not matcher(gadget.text):
            continue
        if register and register not in gadget.registers_written:
            continue
        if category and category not in gadget.categories:
            continue
        if filters.min_stack_change is not None and (
            gadget.stack_change is None
            or gadget.stack_change < filters.min_stack_change
        ):
            continue
        if filters.max_stack_change is not None and (
            gadget.stack_change is None
            or gadget.stack_change > filters.max_stack_change
        ):
            continue
        if filters.address_min is not None and gadget.address < filters.address_min:
            continue
        if filters.address_max is not None and gadget.address > filters.address_max:
            continue
        matched_bad = sorted(
            {
                f"{byte:02x}"
                for byte in gadget.address.to_bytes(width, byteorder, signed=False)
                if byte in filters.bad_bytes
            }
        )
        if matched_bad:
            continue
        output.append(replace(gadget, bad_bytes=matched_bad))

    reverse = filters.order == "desc"
    key = {
        "address": lambda item: item.address,
        "quality": lambda item: item.quality_score,
        "side_effects": lambda item: item.side_effect_count,
        "stack_change": lambda item: (
            item.stack_change is not None,
            item.stack_change if item.stack_change is not None else 0,
        ),
    }.get(filters.sort)
    if key is None:
        raise AnalysisError(f"Unsupported gadget sort: {filters.sort}")
    return sorted(output, key=key, reverse=reverse)


def search_gadgets(gadgets: list[Gadget], query: str) -> list[Gadget]:
    """Compatibility substring search used by deterministic training challenges."""

    needle = query.lower().strip()
    if not needle:
        return gadgets
    return [gadget for gadget in gadgets if needle in gadget.text.lower()]


def simulate_chain(
    gadgets: list[Gadget],
    items: list[dict],
    *,
    bits: int,
    position_independent: bool,
    initial_rsp_mod16: int,
) -> dict:
    """Infer simple stack/register effects for a user-supplied ROP layout.

    This is deliberately not an emulator. Only pop, deterministic rsp adjustment,
    ret, syscall and int 0x80 transitions are modelled.
    """

    width = bits // 8
    by_address = {gadget.address: gadget for gadget in gadgets}
    errors: list[str] = []
    warnings: list[str] = []
    registers: dict[str, dict] = {}
    trace: list[dict] = []
    used: set[int] = set()
    final_target: dict | None = None
    pc_index = 0
    rsp_index = 1
    terminated = False
    visited: set[tuple[int, int]] = set()

    if not items:
        errors.append("The chain is empty.")
    elif items[0]["kind"] != "gadget":
        errors.append("The first chain entry must be a verified gadget address.")

    while not errors and not terminated:
        state = (pc_index, rsp_index)
        if state in visited:
            errors.append("A repeated gadget/stack state was detected.")
            break
        visited.add(state)
        if len(trace) >= len(items) + 1:
            errors.append("The chain exceeded its bounded transition limit.")
            break
        if pc_index >= len(items):
            errors.append("The instruction-pointer entry is outside the chain.")
            break
        current = items[pc_index]
        used.add(pc_index)
        if current["kind"] != "gadget":
            errors.append(f"Entry {pc_index} is not marked as a gadget.")
            break
        gadget = by_address.get(current["value"])
        if gadget is None:
            errors.append(f"Entry {pc_index} does not match a verified gadget address.")
            break

        before = rsp_index
        updates: dict[str, dict] = {}
        next_pc: int | None = None
        step_stopped = False
        if gadget.memory_write:
            warnings.append(
                f"Gadget 0x{gadget.address:x} writes memory; the destination is not modelled."
            )
        if gadget.stack_change is None:
            warnings.append(
                f"Gadget 0x{gadget.address:x} has a data-dependent stack effect."
            )

        for instruction in gadget.instructions:
            mnemonic, _, operands = instruction.partition(" ")
            lower_operands = operands.lower().strip()
            if mnemonic.startswith("pop"):
                if rsp_index >= len(items):
                    errors.append(
                        f"Gadget 0x{gadget.address:x} requires a stack value for {instruction}."
                    )
                    step_stopped = True
                    break
                value_item = items[rsp_index]
                used.add(rsp_index)
                if lower_operands in gadget.popped_registers:
                    update = _value_report(value_item, rsp_index)
                    registers[lower_operands] = update
                    updates[lower_operands] = update
                else:
                    warnings.append(
                        f"{instruction} consumes a stack value but its destination is not modelled."
                    )
                rsp_index += 1
            elif mnemonic.startswith("push"):
                errors.append(
                    f"Backward stack write from {instruction} is not modelled."
                )
                step_stopped = True
                break
            elif mnemonic == "call":
                warnings.append(
                    f"{instruction} transfers control into unmodelled code; simulation stopped."
                )
                terminated = True
                step_stopped = True
                break
            elif mnemonic in {"add", "sub"} and lower_operands.startswith(
                ("rsp,", "esp,")
            ):
                immediate = _parse_immediate(lower_operands.split(",", 1)[1])
                if immediate is None or immediate % width:
                    errors.append(
                        f"Unaligned or unknown stack adjustment in gadget 0x{gadget.address:x}."
                    )
                    step_stopped = True
                    break
                if mnemonic == "sub":
                    errors.append(
                        f"Backward stack adjustment in gadget 0x{gadget.address:x} is not modelled."
                    )
                    step_stopped = True
                    break
                skip = immediate // width
                if rsp_index + skip > len(items):
                    errors.append(
                        f"Gadget 0x{gadget.address:x} skips beyond the supplied chain."
                    )
                    step_stopped = True
                    break
                used.update(range(rsp_index, rsp_index + skip))
                rsp_index += skip
            elif mnemonic == "leave":
                warnings.append(
                    "leave depends on the runtime frame pointer; simulation stopped."
                )
                terminated = True
                step_stopped = True
                break
            elif "stack_pivot" in gadget.categories and mnemonic in {"mov", "xchg"}:
                warnings.append(
                    f"{instruction} makes RSP data-dependent; simulation stopped."
                )
                terminated = True
                step_stopped = True
                break
            elif mnemonic == "ret":
                if rsp_index >= len(items):
                    warnings.append(
                        f"Gadget 0x{gadget.address:x} returns beyond the supplied chain."
                    )
                    terminated = True
                    step_stopped = True
                    break
                next_pc = rsp_index
                used.add(next_pc)
                rsp_index += 1
                immediate = _parse_immediate(lower_operands) if lower_operands else 0
                if immediate is None or immediate % width:
                    errors.append(
                        "ret uses an unaligned or unknown immediate stack adjustment."
                    )
                    step_stopped = True
                    break
                skip = immediate // width
                if rsp_index + skip > len(items):
                    errors.append("ret immediate skips beyond the supplied chain.")
                    step_stopped = True
                    break
                used.update(range(rsp_index, rsp_index + skip))
                rsp_index += skip
                target_item = items[next_pc]
                if target_item["kind"] != "gadget":
                    final_target = _value_report(target_item, next_pc)
                    terminated = True
                break
            elif mnemonic == "syscall" or instruction.lower() == "int 0x80":
                final_target = {
                    "kind": "effect",
                    "label": instruction.lower(),
                    "verification": "inferred",
                }
                terminated = True
                break

        for register in gadget.registers_written:
            if register not in _STACK_REGISTERS and register not in updates:
                registers[register] = {
                    "value": None,
                    "value_hex": None,
                    "source_index": pc_index,
                    "verification": "unknown",
                }
        trace.append(
            {
                "gadget_address": gadget.address,
                "gadget_text": gadget.text,
                "chain_index": pc_index,
                "rsp_before": (before - 1) * width,
                "rsp_after": (rsp_index - 1) * width,
                "register_updates": updates,
                "quality_score": gadget.quality_score,
            }
        )
        if errors or terminated or step_stopped:
            break
        if next_pc is None:
            warnings.append(
                f"Gadget 0x{gadget.address:x} has no modelled continuation."
            )
            break
        pc_index = next_pc

    unused = sorted(set(range(len(items))) - used)
    if unused:
        warnings.append(
            "Some chain entries were not consumed: " + ", ".join(map(str, unused))
        )
    if position_independent:
        warnings.append(
            "PIE is enabled; gadget values are image offsets until a runtime base is known."
        )
    warnings = list(dict.fromkeys(warnings))
    status = "invalid" if errors else "warning" if warnings else "valid"
    rsp_delta = max(0, (rsp_index - 1) * width)
    return {
        "status": status,
        "verification": "inferred",
        "success_verified": False,
        "meaning": (
            "Valid means the supplied layout is internally consistent under this limited "
            "static model; runtime exploit success was not tested."
        ),
        "confidence": 0.0 if errors else 0.72 if warnings else 0.86,
        "bits": bits,
        "entry_count": len(items),
        "consumed_entries": len(used),
        "rsp_delta": rsp_delta,
        "final_rsp_mod16": (initial_rsp_mod16 + rsp_delta) % 16,
        "registers": registers,
        "trace": trace,
        "final_target": final_target,
        "errors": errors,
        "warnings": warnings,
        "limitations": [
            "This is a static stack-effect model, not CPU emulation",
            "Memory values, branch conditions, called code, syscalls, and runtime mappings are not executed",
        ],
    }


def _terminal_ranges(blob: bytes):  # noqa: ANN202
    for index, byte in enumerate(blob):
        if byte == 0xC3:
            yield index, index + 1
        elif byte == 0xC2 and index + 2 < len(blob):
            yield index, index + 3
        elif byte == 0x0F and index + 1 < len(blob) and blob[index + 1] == 0x05:
            yield index, index + 2
        elif byte == 0xCD and index + 1 < len(blob) and blob[index + 1] == 0x80:
            yield index, index + 2


def _indirect_terminals(engine: Cs, blob: bytes):  # noqa: ANN202
    """간접 분기(JOP/COP) 종단 ``jmp/call reg`` · ``jmp/call [mem]`` 을 찾는다.

    ``0xFF`` opcode + ModRM reg 필드가 2(call r/m) 또는 4(jmp r/m)인 near 간접
    분기만 대상으로 한다. 상대 분기(E8/E9)와 far 변형은 제외한다. 정확한 종단
    길이는 Capstone 으로 1개 명령을 디코드해 확정하며, 최종 종단 인정은
    :func:`_is_terminal` 이 다시 검증한다. REX prefix(0x40–0x4F)가 앞선 경우도 포함.
    """

    length = len(blob)
    for index, byte in enumerate(blob):
        opcode_index = index
        if 0x40 <= byte <= 0x4F and index + 1 < length and blob[index + 1] == 0xFF:
            opcode_index = index + 1
        elif byte != 0xFF:
            continue
        if opcode_index + 1 >= length:
            continue
        reg_field = (blob[opcode_index + 1] >> 3) & 0x7
        if reg_field not in (2, 4):  # 2=call r/m, 4=jmp r/m (near, indirect)
            continue
        decoded = next(iter(engine.disasm(blob[index : index + 15], 0)), None)
        if decoded is None or not _is_terminal(decoded):
            continue
        yield index, index + decoded.size


def _decode_gadget(
    engine: Cs,
    blob: bytes,
    start: int,
    end: int,
    base: int,
    section: str,
    image: ElfImage,
    image_base: int,
    max_depth: int,
) -> Gadget | None:
    code = blob[start:end]
    decoded = list(islice(engine.disasm(code, base + start), max_depth + 1))
    if len(decoded) > max_depth or not decoded:
        return None
    if sum(instruction.size for instruction in decoded) != len(code):
        return None
    if not _is_terminal(decoded[-1]):
        return None
    for instruction in decoded[:-1]:
        if instruction.group(CS_GRP_RET) or instruction.group(CS_GRP_JUMP):
            return None

    instructions = [
        (
            instruction.mnemonic
            if not instruction.op_str
            else f"{instruction.mnemonic} {instruction.op_str}"
        )
        for instruction in decoded
    ]
    effects = _instruction_effects(decoded, image.bits)
    address = base + start
    position_independent = image.e_type == "ET_DYN"
    quality_score = _quality_score(decoded, effects)
    return Gadget(
        address=address,
        bytes_hex=code.hex(),
        instructions=instructions,
        section=section,
        terminator=instructions[-1],
        stack_change=effects["stack_change"],
        stack_words=(
            effects["stack_change"] // (image.bits // 8)
            if effects["stack_change"] is not None
            and effects["stack_change"] % (image.bits // 8) == 0
            else None
        ),
        registers_read=effects["registers_read"],
        registers_written=effects["registers_written"],
        popped_registers=effects["popped_registers"],
        memory_read=effects["memory_read"],
        memory_write=effects["memory_write"],
        categories=effects["categories"],
        side_effect_count=effects["side_effect_count"],
        quality_score=quality_score,
        pie_offset=address - image_base if position_independent else None,
        position_independent=position_independent,
        evidence=[
            f"Exact bytes from executable section {section}",
            f"Capstone decoded {len(decoded)} instruction(s) ending in {instructions[-1]}",
        ],
    )


def _instruction_effects(decoded: list, bits: int) -> dict:  # noqa: ANN001
    word = bits // 8
    registers_read: set[str] = set()
    registers_written: set[str] = set()
    popped_registers: list[str] = []
    categories: set[str] = set()
    stack_change = 0
    stack_known = True
    memory_read = False
    memory_write = False
    explained_stack_writes: set[int] = set()

    for index, instruction in enumerate(decoded):
        read_ids, written_ids = instruction.regs_access()
        reads = {instruction.reg_name(item) for item in read_ids}
        writes = {instruction.reg_name(item) for item in written_ids}
        registers_read.update(name for name in reads if name)
        registers_written.update(name for name in writes if name)
        mnemonic = instruction.mnemonic.lower()

        for operand_index, operand in enumerate(instruction.operands):
            if operand.type != X86_OP_MEM:
                continue
            if operand.access & CS_AC_READ:
                memory_read = True
            if operand.access & CS_AC_WRITE:
                memory_write = True
            if not operand.access and mnemonic != "lea":
                memory_read = True
            if operand_index == 0 and operand.access & CS_AC_WRITE:
                memory_write = True

        if mnemonic.startswith("pop"):
            stack_change += word
            memory_read = True
            explained_stack_writes.add(index)
            if instruction.operands and instruction.operands[0].type == X86_OP_REG:
                popped_registers.append(
                    instruction.reg_name(instruction.operands[0].reg)
                )
        elif mnemonic.startswith("push"):
            stack_change -= word
            memory_write = True
            explained_stack_writes.add(index)
        elif mnemonic == "ret":
            stack_change += word
            memory_read = True
            explained_stack_writes.add(index)
            if instruction.operands and instruction.operands[0].type == X86_OP_IMM:
                stack_change += int(instruction.operands[0].imm)
        elif mnemonic == "leave":
            stack_known = False
            memory_read = True
            categories.add("stack_pivot")
            explained_stack_writes.add(index)
        elif mnemonic in {"add", "sub"} and len(instruction.operands) >= 2:
            destination, immediate = instruction.operands[:2]
            if (
                destination.type == X86_OP_REG
                and instruction.reg_name(destination.reg) in _STACK_REGISTERS
            ):
                explained_stack_writes.add(index)
                categories.add("stack_adjust")
                if immediate.type != X86_OP_IMM:
                    stack_known = False
                else:
                    value = int(immediate.imm)
                    stack_change += value if mnemonic == "add" else -value
        elif instruction.group(CS_GRP_CALL):
            stack_known = False
            memory_write = True

        if mnemonic == "syscall":
            categories.add("syscall")
        if mnemonic == "int" and instruction.op_str.lower() == "0x80":
            categories.add("int80")
        if mnemonic == "xchg":
            categories.add("xchg")
        if mnemonic.startswith("mov"):
            categories.add("move")
        if instruction.group(CS_GRP_CALL) and instruction.operands:
            if instruction.operands[0].type == X86_OP_REG:
                categories.add("call_register")
        if instruction.group(CS_GRP_JUMP) and instruction.operands:
            if instruction.operands[0].type == X86_OP_REG:
                categories.add("jump_register")

    if decoded[-1].group(CS_GRP_RET):
        categories.add("return")
    if popped_registers:
        categories.add("pop")
    if len(popped_registers) > 1:
        categories.add("multi_pop")
    if memory_write:
        categories.add("memory_write")
        first = decoded[0]
        if (
            first.mnemonic.lower().startswith("mov")
            and first.operands
            and first.operands[0].type == X86_OP_MEM
        ):
            categories.add("write_what_where_candidate")

    for index, instruction in enumerate(decoded):
        _, written_ids = instruction.regs_access()
        written = {instruction.reg_name(item) for item in written_ids}
        if written & _STACK_REGISTERS and index not in explained_stack_writes:
            stack_known = False
            categories.add("stack_pivot")

    intentional = set(popped_registers) | _STACK_REGISTERS
    clobbered = registers_written - intentional
    side_effect_count = len(clobbered) + (2 if memory_write else 0)
    return {
        "stack_change": stack_change if stack_known else None,
        "registers_read": sorted(registers_read),
        "registers_written": sorted(registers_written),
        "popped_registers": popped_registers,
        "memory_read": memory_read,
        "memory_write": memory_write,
        "categories": sorted(categories),
        "side_effect_count": side_effect_count,
    }


def _quality_score(decoded: list, effects: dict) -> float:  # noqa: ANN001
    score = 1.0 - max(0, len(decoded) - 1) * 0.035
    score -= effects["side_effect_count"] * 0.035
    if effects["memory_write"]:
        score -= 0.12
    if effects["stack_change"] is None:
        score -= 0.2
    if any(instruction.group(CS_GRP_CALL) for instruction in decoded[:-1]):
        score -= 0.12
    return float(round(max(0.05, min(1.0, score)), 2))


def _is_terminal(instruction) -> bool:  # noqa: ANN001
    if instruction.group(CS_GRP_RET):
        return True
    if instruction.mnemonic.lower() == "syscall":
        return True
    if instruction.mnemonic.lower() == "int" and instruction.op_str.lower() == "0x80":
        return True
    if instruction.group(CS_GRP_JUMP) or instruction.group(CS_GRP_CALL):
        # 간접 분기(jmp/call reg 또는 [mem])만 JOP/COP 종단으로 인정한다.
        # 상대 분기(jmp/call rel)는 제어를 뺏기지 않으므로 제외.
        operands = instruction.operands
        return bool(operands) and operands[0].type in (X86_OP_REG, X86_OP_MEM)
    return False


def _image_base(image: ElfImage) -> int:
    loads = [segment.vaddr for segment in image.segments if segment.ptype == "PT_LOAD"]
    return min(loads) if loads else 0


def _sorted(seen: dict[int, Gadget]) -> list[Gadget]:
    return [seen[address] for address in sorted(seen)]


def _query_matcher(query: str, regex: bool):  # noqa: ANN202
    query = query.strip()
    if not query:
        return None
    if not regex:
        needle = query.lower()
        return lambda value: needle in value.lower()
    if len(query) > 128 or not _SAFE_REGEX_META.fullmatch(query):
        raise AnalysisError(
            "Regex must use the bounded character-class syntax and be at most 128 characters."
        )
    if query.count("*") + query.count("+") + query.count("?") > 4:
        raise AnalysisError("Regex contains too many repetition operators.")
    try:
        pattern = re.compile(query, re.IGNORECASE)
    except re.error as exc:
        raise AnalysisError(f"Invalid gadget regex: {exc}") from exc
    return lambda value: pattern.search(value) is not None


def _parse_immediate(value: str) -> int | None:
    try:
        return int(value.strip(), 0)
    except ValueError:
        return None


def _value_report(item: dict, index: int) -> dict:
    value = int(item["value"])
    return {
        "kind": item["kind"],
        "label": item.get("label") or "",
        "value": value,
        "value_hex": f"0x{value:x}",
        "source_index": index,
        "verification": "verified" if item["kind"] == "gadget" else "user_provided",
    }
