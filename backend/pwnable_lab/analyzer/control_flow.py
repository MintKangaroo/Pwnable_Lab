"""Bounded x86/x86-64 function, xref, and control-flow analysis.

Function addresses from loader metadata or symbols remain distinct from boundaries
inferred from neighbouring functions. Raw blobs are intentionally excluded because
they have no verified architecture, load map, or entry point.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from itertools import islice

from capstone import (  # type: ignore[import-untyped]
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
    X86_REG_RIP,
)

from pwnable_lab.elf.parser import ElfImage
from pwnable_lab.errors import AnalysisError
from pwnable_lab.pe.parser import PEImage

_SUPPORTED_ELF_MACHINES = {"EM_386", "EM_X86_64"}
_SUPPORTED_PE_MACHINES = {
    "IMAGE_FILE_MACHINE_I386",
    "IMAGE_FILE_MACHINE_AMD64",
}


@dataclass(frozen=True)
class CodeRegion:
    name: str
    address: int
    data: bytes = field(repr=False)

    @property
    def end(self) -> int:
        return self.address + len(self.data)

    def contains(self, address: int) -> bool:
        return self.address <= address < self.end


@dataclass(frozen=True)
class FunctionSeed:
    address: int
    name: str
    size: int
    source: str
    address_verification: str
    confidence: float
    evidence: str


@dataclass
class FunctionInfo:
    address: int
    end: int
    size: int
    name: str
    aliases: list[str]
    region: str
    source: str
    address_verification: str
    boundary_verification: str
    verification: str
    confidence: float
    evidence: list[str]


@dataclass(frozen=True)
class FlowInstruction:
    address: int
    size: int
    mnemonic: str
    op_str: str
    bytes_hex: str
    target: int | None
    target_kind: str | None
    is_call: bool
    is_jump: bool
    is_conditional: bool
    is_return: bool

    @property
    def text(self) -> str:
        return self.mnemonic if not self.op_str else f"{self.mnemonic} {self.op_str}"

    def as_dict(self) -> dict:
        result = asdict(self)
        result["text"] = self.text
        return result


@dataclass(frozen=True)
class XrefInfo:
    source: int
    target: int
    kind: str
    target_kind: str
    source_function: str | None
    target_function: str | None
    target_symbol: str | None
    instruction: str
    verification: str = "verified"
    confidence: float = 1.0


class ControlFlowAnalyzer:
    def __init__(
        self,
        *,
        artifact_format: str,
        machine: str,
        bits: int,
        entry: int,
        regions: list[CodeRegion],
        seeds: list[FunctionSeed],
        symbols: dict[int, list[str]],
    ) -> None:
        if bits not in {32, 64}:
            raise AnalysisError(f"Unsupported control-flow bitness: {bits}")
        self.artifact_format = artifact_format
        self.machine = machine
        self.bits = bits
        self.entry = entry
        self.regions = sorted(regions, key=lambda item: item.address)
        self.seeds = seeds
        self.symbols = symbols

    @classmethod
    def from_elf(cls, image: ElfImage) -> ControlFlowAnalyzer:
        if image.machine not in _SUPPORTED_ELF_MACHINES:
            raise AnalysisError(
                f"Control-flow analysis supports x86/x86-64 ELF only: {image.machine}"
            )
        regions = [
            CodeRegion(
                section.name or f"section_{section.addr:x}",
                section.addr,
                image.data[section.offset : section.offset + section.size],
            )
            for section in image.sections
            if section.executable and section.size
        ]
        seeds: list[FunctionSeed] = []
        symbols: dict[int, list[str]] = {}
        for symbol in image.symbols + image.dynamic_symbols:
            if symbol.name and symbol.addr:
                symbols.setdefault(symbol.addr, []).append(symbol.name)
            if not (
                symbol.name
                and symbol.addr
                and symbol.defined
                and symbol.stype == "STT_FUNC"
            ):
                continue
            seeds.append(
                FunctionSeed(
                    address=symbol.addr,
                    name=symbol.name,
                    size=max(0, symbol.size),
                    source="symbol",
                    address_verification="verified",
                    confidence=1.0,
                    evidence=f"Defined STT_FUNC symbol {symbol.name} at 0x{symbol.addr:x}",
                )
            )
        if image.entry:
            seeds.append(
                FunctionSeed(
                    address=image.entry,
                    name="entry",
                    size=0,
                    source="elf_header",
                    address_verification="verified",
                    confidence=1.0,
                    evidence=f"ELF entry point is 0x{image.entry:x}",
                )
            )
        return cls(
            artifact_format="ELF",
            machine=image.machine,
            bits=image.bits,
            entry=image.entry,
            regions=regions,
            seeds=seeds,
            symbols=symbols,
        )

    @classmethod
    def from_pe(cls, image: PEImage) -> ControlFlowAnalyzer:
        if image.machine not in _SUPPORTED_PE_MACHINES:
            raise AnalysisError(
                f"Control-flow analysis supports x86/x86-64 PE only: {image.machine}"
            )
        regions = [
            CodeRegion(
                section.name or f"section_{section.addr:x}",
                section.addr,
                image.data[section.offset : section.offset + section.size],
            )
            for section in image.sections
            if section.executable and section.size
        ]
        seeds = [
            FunctionSeed(
                address=item.address,
                name=item.name,
                size=0,
                source="export",
                address_verification="verified",
                confidence=1.0,
                evidence=f"PE export {item.name} resolves to 0x{item.address:x}",
            )
            for item in image.exports
        ]
        if image.entry:
            seeds.append(
                FunctionSeed(
                    address=image.entry,
                    name="entry",
                    size=0,
                    source="pe_header",
                    address_verification="verified",
                    confidence=1.0,
                    evidence=f"PE AddressOfEntryPoint resolves to 0x{image.entry:x}",
                )
            )
        symbols: dict[int, list[str]] = {}
        for export in image.exports:
            symbols.setdefault(export.address, []).append(export.name)
        for imported in image.imports:
            symbols.setdefault(imported.address, []).append(
                f"{imported.library}!{imported.name}"
            )
        return cls(
            artifact_format="PE",
            machine=image.machine,
            bits=image.bits,
            entry=image.entry,
            regions=regions,
            seeds=seeds,
            symbols=symbols,
        )

    def functions(self, *, max_instructions: int) -> tuple[list[FunctionInfo], bool]:
        discovered, scan_truncated = self._direct_call_seeds(
            max_instructions=max_instructions
        )
        by_address: dict[int, list[FunctionSeed]] = {}
        for seed in [*self.seeds, *discovered]:
            if self._region(seed.address) is not None:
                by_address.setdefault(seed.address, []).append(seed)

        output: list[FunctionInfo] = []
        for region in self.regions:
            addresses = sorted(
                address for address in by_address if region.contains(address)
            )
            for index, address in enumerate(addresses):
                candidates = by_address[address]
                preferred = min(candidates, key=_seed_priority)
                next_address = (
                    addresses[index + 1] if index + 1 < len(addresses) else region.end
                )
                declared_end = address + preferred.size
                size_verified = (
                    preferred.size > 0 and address < declared_end <= region.end
                )
                end = declared_end if size_verified else next_address
                if end <= address:
                    continue
                aliases = sorted({item.name for item in candidates if item.name})
                boundary_verification = "verified" if size_verified else "inferred"
                verification = (
                    "verified"
                    if preferred.address_verification == "verified" and size_verified
                    else "inferred"
                )
                evidence = [item.evidence for item in candidates]
                if size_verified:
                    evidence.append(f"Symbol size defines the end address 0x{end:x}")
                else:
                    evidence.append(
                        f"End address 0x{end:x} is inferred from the next function or region boundary"
                    )
                output.append(
                    FunctionInfo(
                        address=address,
                        end=end,
                        size=end - address,
                        name=preferred.name or f"sub_{address:x}",
                        aliases=aliases,
                        region=region.name,
                        source=preferred.source,
                        address_verification=preferred.address_verification,
                        boundary_verification=boundary_verification,
                        verification=verification,
                        confidence=(
                            preferred.confidence
                            if size_verified
                            else min(0.82, preferred.confidence)
                        ),
                        evidence=evidence,
                    )
                )
        return sorted(output, key=lambda item: item.address), scan_truncated

    def function_detail(self, address: int, *, max_instructions: int) -> dict:
        functions, discovery_truncated = self.functions(
            max_instructions=max_instructions
        )
        function = _select_function(functions, address)
        instructions, decode_truncated = self._decode_range(
            function.address,
            function.end,
            max_instructions=max_instructions,
        )
        result = asdict(function)
        result.update(
            {
                "instructions": [item.as_dict() for item in instructions],
                "instruction_count": len(instructions),
                "truncated": discovery_truncated or decode_truncated,
            }
        )
        return result

    def cfg(self, address: int, *, max_instructions: int) -> dict:
        functions, discovery_truncated = self.functions(
            max_instructions=max_instructions
        )
        function = _select_function(functions, address)
        instructions, decode_truncated = self._decode_range(
            function.address,
            function.end,
            max_instructions=max_instructions,
        )
        nodes, edges = _build_blocks(function, instructions)
        return {
            "format": self.artifact_format,
            "function": asdict(function),
            "nodes": nodes,
            "edges": edges,
            "node_count": len(nodes),
            "edge_count": len(edges),
            "status": (
                "partially_completed"
                if discovery_truncated or decode_truncated
                else "completed"
            ),
            "verification": (
                "verified" if function.verification == "verified" else "inferred"
            ),
            "confidence": function.confidence,
            "limitations": [
                "Only statically resolved direct branch targets create CFG edges",
                "Indirect jump targets require later data-flow or runtime analysis",
            ],
        }

    def xrefs(
        self,
        *,
        address: int | None,
        direction: str,
        kind: str,
        max_instructions: int,
    ) -> tuple[list[XrefInfo], bool]:
        functions, discovery_truncated = self.functions(
            max_instructions=max_instructions
        )
        instructions, decode_truncated = self._decode_all(
            max_instructions=max_instructions
        )
        output: list[XrefInfo] = []
        for instruction in instructions:
            if instruction.target is None or not (
                instruction.is_call or instruction.is_jump
            ):
                continue
            xref_kind = (
                "call"
                if instruction.is_call
                else "conditional_jump" if instruction.is_conditional else "jump"
            )
            if kind != "all" and kind != xref_kind:
                continue
            if address is not None:
                compared = (
                    instruction.target if direction == "to" else instruction.address
                )
                if compared != address:
                    continue
            source_function = _function_containing(functions, instruction.address)
            target_function = _function_containing(functions, instruction.target)
            names = self.symbols.get(instruction.target, [])
            output.append(
                XrefInfo(
                    source=instruction.address,
                    target=instruction.target,
                    kind=xref_kind,
                    target_kind=instruction.target_kind or "code",
                    source_function=source_function.name if source_function else None,
                    target_function=target_function.name if target_function else None,
                    target_symbol=names[0] if names else None,
                    instruction=instruction.text,
                )
            )
        return output, discovery_truncated or decode_truncated

    def _direct_call_seeds(
        self, *, max_instructions: int
    ) -> tuple[list[FunctionSeed], bool]:
        instructions, truncated = self._decode_all(max_instructions=max_instructions)
        output: list[FunctionSeed] = []
        seen: set[int] = set()
        for instruction in instructions:
            if (
                not instruction.is_call
                or instruction.target is None
                or instruction.target_kind != "code"
                or instruction.target in seen
                or self._region(instruction.target) is None
            ):
                continue
            seen.add(instruction.target)
            names = self.symbols.get(instruction.target, [])
            output.append(
                FunctionSeed(
                    address=instruction.target,
                    name=names[0] if names else f"sub_{instruction.target:x}",
                    size=0,
                    source="direct_call",
                    address_verification="inferred",
                    confidence=0.72,
                    evidence=(
                        f"Direct call at 0x{instruction.address:x} targets executable address "
                        f"0x{instruction.target:x}"
                    ),
                )
            )
        return output, truncated

    def _decode_all(
        self, *, max_instructions: int
    ) -> tuple[list[FlowInstruction], bool]:
        output: list[FlowInstruction] = []
        remaining = max(1, max_instructions)
        truncated = False
        for region in self.regions:
            decoded, region_truncated = self._decode_blob(
                region.data,
                region.address,
                max_instructions=remaining,
            )
            output.extend(decoded)
            remaining -= len(decoded)
            if region_truncated or remaining <= 0:
                truncated = True
                break
        return output, truncated

    def _decode_range(
        self, start: int, end: int, *, max_instructions: int
    ) -> tuple[list[FlowInstruction], bool]:
        region = self._region(start)
        if region is None or end > region.end:
            raise AnalysisError(
                "Function range is outside executable file-backed bytes."
            )
        offset = start - region.address
        return self._decode_blob(
            region.data[offset : offset + (end - start)],
            start,
            max_instructions=max_instructions,
        )

    def _decode_blob(
        self, data: bytes, address: int, *, max_instructions: int
    ) -> tuple[list[FlowInstruction], bool]:
        engine = Cs(CS_ARCH_X86, CS_MODE_64 if self.bits == 64 else CS_MODE_32)
        engine.detail = True
        decoded = list(islice(engine.disasm(data, address), max_instructions + 1))
        truncated = len(decoded) > max_instructions
        selected = decoded[:max_instructions]
        return [_normalize_instruction(item) for item in selected], truncated

    def _region(self, address: int) -> CodeRegion | None:
        return next((item for item in self.regions if item.contains(address)), None)


def _normalize_instruction(instruction) -> FlowInstruction:  # noqa: ANN001
    is_call = instruction.group(CS_GRP_CALL)
    is_jump = instruction.group(CS_GRP_JUMP)
    is_return = instruction.group(CS_GRP_RET)
    is_conditional = is_jump and instruction.mnemonic.lower() != "jmp"
    target: int | None = None
    target_kind: str | None = None
    if (is_call or is_jump) and instruction.operands:
        operand = instruction.operands[0]
        if operand.type == X86_OP_IMM:
            target = int(operand.imm)
            target_kind = "code"
        elif operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
            target = int(instruction.address + instruction.size + operand.mem.disp)
            target_kind = "memory"
    return FlowInstruction(
        address=int(instruction.address),
        size=int(instruction.size),
        mnemonic=instruction.mnemonic,
        op_str=instruction.op_str,
        bytes_hex=instruction.bytes.hex(),
        target=target,
        target_kind=target_kind,
        is_call=bool(is_call),
        is_jump=bool(is_jump),
        is_conditional=bool(is_conditional),
        is_return=bool(is_return),
    )


def _build_blocks(
    function: FunctionInfo, instructions: list[FlowInstruction]
) -> tuple[list[dict], list[dict]]:
    if not instructions:
        return [], []
    addresses = {item.address for item in instructions}
    leaders = {instructions[0].address}
    for index, instruction in enumerate(instructions):
        next_address = (
            instructions[index + 1].address if index + 1 < len(instructions) else None
        )
        if instruction.is_jump and instruction.target in addresses:
            assert instruction.target is not None
            leaders.add(instruction.target)
        if next_address is not None and (
            instruction.is_conditional or instruction.is_return or instruction.is_jump
        ):
            leaders.add(next_address)

    blocks: list[list[FlowInstruction]] = []
    current: list[FlowInstruction] = []
    for instruction in instructions:
        if current and instruction.address in leaders:
            blocks.append(current)
            current = []
        current.append(instruction)
    if current:
        blocks.append(current)

    block_starts = {block[0].address for block in blocks}
    edges: list[dict] = []
    for index, block in enumerate(blocks):
        last = block[-1]
        fallthrough = blocks[index + 1][0].address if index + 1 < len(blocks) else None
        if last.is_jump:
            if last.target in block_starts:
                edges.append(
                    _edge(
                        block[0].address,
                        last.target,
                        "true" if last.is_conditional else "jump",
                    )
                )
            if last.is_conditional and fallthrough is not None:
                edges.append(_edge(block[0].address, fallthrough, "false"))
        elif not last.is_return and fallthrough is not None:
            edges.append(_edge(block[0].address, fallthrough, "fallthrough"))

    predecessors: dict[int, list[int]] = {start: [] for start in block_starts}
    successors: dict[int, list[int]] = {start: [] for start in block_starts}
    for edge in edges:
        predecessors[edge["target"]].append(edge["source"])
        successors[edge["source"]].append(edge["target"])

    nodes = []
    for block in blocks:
        start = block[0].address
        end = block[-1].address + block[-1].size
        nodes.append(
            {
                "id": f"block-{start:x}",
                "start": start,
                "end": end,
                "instructions": [item.as_dict() for item in block],
                "predecessors": sorted(predecessors[start]),
                "successors": sorted(successors[start]),
                "call_targets": sorted(
                    {
                        item.target
                        for item in block
                        if item.is_call and item.target is not None
                    }
                ),
                "conditional_branch": block[-1].is_conditional,
                "verification": function.verification,
            }
        )
    return nodes, edges


def _edge(source: int, target: int, edge_type: str) -> dict:
    return {
        "id": f"{source:x}-{target:x}-{edge_type}",
        "source": source,
        "target": target,
        "type": edge_type,
        "verification": "verified",
    }


def _seed_priority(seed: FunctionSeed) -> tuple[int, int, str]:
    source_order = {
        "symbol": 0,
        "export": 0,
        "elf_header": 1,
        "pe_header": 1,
        "direct_call": 2,
    }
    return (source_order.get(seed.source, 3), 0 if seed.size else 1, seed.name)


def _select_function(functions: list[FunctionInfo], address: int) -> FunctionInfo:
    exact = next((item for item in functions if item.address == address), None)
    if exact is not None:
        return exact
    containing = _function_containing(functions, address)
    if containing is None:
        raise AnalysisError(f"No discovered function contains address 0x{address:x}.")
    return containing


def _function_containing(
    functions: list[FunctionInfo], address: int
) -> FunctionInfo | None:
    return next(
        (item for item in functions if item.address <= address < item.end),
        None,
    )
