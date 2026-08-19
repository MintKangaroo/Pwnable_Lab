"""위험 API와 정적 호출 위치를 근거로 공격 표면 후보를 분류한다.

함수 import만으로 취약점을 확정하지 않는다. 직접 호출 위치를 찾은 경우에도 인자 값과
데이터 흐름은 제한적으로만 추정하며 모든 결과를 ``possible`` 상태로 반환한다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from itertools import islice

from capstone import (  # type: ignore[import-untyped]
    CS_ARCH_X86,
    CS_MODE_32,
    CS_MODE_64,
    Cs,
)

from pwnable_lab.analyzer.got_plt import analyze_got_plt
from pwnable_lab.elf.parser import ElfImage, SymbolInfo

# 함수명 -> (카테고리, 심각도, 설명)
_DANGEROUS: dict[str, tuple[str, str, str]] = {
    "gets": ("memory-corruption", "critical", "길이 제한이 없는 입력 함수입니다."),
    "strcpy": ("memory-corruption", "high", "대상 버퍼 크기를 확인하지 않습니다."),
    "strcat": ("memory-corruption", "high", "경계 검사가 없는 문자열 연결입니다."),
    "sprintf": ("memory-corruption", "high", "출력 길이 제한이 없습니다."),
    "vsprintf": ("memory-corruption", "high", "가변 인자 출력 길이 제한이 없습니다."),
    "scanf": ("memory-corruption", "medium", "%s 폭 지정 등 포맷 검증이 필요합니다."),
    "sscanf": ("memory-corruption", "medium", "대상 크기와 포맷 폭 검증이 필요합니다."),
    "memcpy": (
        "memory-corruption",
        "info",
        "길이와 대상 객체 크기의 관계를 확인해야 합니다.",
    ),
    "memmove": (
        "memory-corruption",
        "info",
        "길이와 대상 객체 크기의 관계를 확인해야 합니다.",
    ),
    "read": ("memory-corruption", "info", "길이 인자가 버퍼보다 큰지 확인해야 합니다."),
    "recv": ("memory-corruption", "info", "수신 길이와 버퍼 크기를 비교해야 합니다."),
    "fgets": (
        "memory-corruption",
        "info",
        "크기 인자가 실제 버퍼 크기와 일치하는지 확인해야 합니다.",
    ),
    "strncpy": ("memory-corruption", "info", "종단 NUL과 길이 계산을 확인해야 합니다."),
    "printf": (
        "format-string",
        "medium",
        "포맷 인자가 사용자 제어인지 확인해야 합니다.",
    ),
    "fprintf": (
        "format-string",
        "medium",
        "포맷 인자가 사용자 제어인지 확인해야 합니다.",
    ),
    "snprintf": (
        "format-string",
        "info",
        "포맷 인자가 사용자 제어인지 확인해야 합니다.",
    ),
    "syslog": (
        "format-string",
        "medium",
        "포맷 인자가 사용자 제어인지 확인해야 합니다.",
    ),
    "system": (
        "command-execution",
        "critical",
        "셸 명령 인자의 신뢰 경계를 확인해야 합니다.",
    ),
    "execve": (
        "command-execution",
        "high",
        "실행 경로와 인자의 제어 가능성을 확인해야 합니다.",
    ),
    "execl": (
        "command-execution",
        "high",
        "실행 경로와 인자의 제어 가능성을 확인해야 합니다.",
    ),
    "popen": (
        "command-execution",
        "high",
        "셸을 통한 명령 실행 인자를 확인해야 합니다.",
    ),
    "malloc": ("heap", "info", "할당 크기 계산과 생명주기를 확인해야 합니다."),
    "calloc": ("heap", "info", "곱셈 크기와 생명주기를 확인해야 합니다."),
    "realloc": ("heap", "info", "실패 처리와 이전 포인터 생명주기를 확인해야 합니다."),
    "free": ("heap", "info", "이중 해제와 해제 후 사용 여부를 확인해야 합니다."),
    "open": ("file-input", "info", "경로와 플래그의 신뢰 경계를 확인해야 합니다."),
    "fopen": ("file-input", "info", "경로와 모드의 신뢰 경계를 확인해야 합니다."),
    "getline": ("file-input", "info", "할당된 입력의 길이 사용처를 추적해야 합니다."),
    "alloca": ("stack", "medium", "사용자 제어 크기의 스택 할당인지 확인해야 합니다."),
}

_ORDER = {"critical": 0, "high": 1, "medium": 2, "info": 3}
_X64_ARGUMENT_REGISTERS = (
    ("rdi", {"rdi", "edi", "di"}),
    ("rsi", {"rsi", "esi", "si"}),
    ("rdx", {"rdx", "edx", "dx"}),
    ("rcx", {"rcx", "ecx", "cx"}),
    ("r8", {"r8", "r8d", "r8w"}),
    ("r9", {"r9", "r9d", "r9w"}),
)
_FORTIFIED_ALIASES = {
    # GCC may replace strcpy()+strlen() with the semantically related checked stpcpy.
    "stpcpy": "strcpy",
}


@dataclass
class CallSite:
    address: int
    target_address: int
    function: str | None
    calling_convention: str
    arguments: dict[str, str]
    surrounding_disassembly: list[str]
    verification: str = "inferred"
    confidence: float = 0.86


@dataclass
class Finding:
    symbol: str
    category: str
    severity: str
    description: str
    status: str = "possible"
    address: int | None = None
    call_sites: list[CallSite] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    false_positive_factors: list[str] = field(default_factory=list)
    confidence: float = 0.3
    verification: str = "inferred"


def scan_vulns(image: ElfImage, *, max_instructions: int = 20_000) -> list[Finding]:
    """위험 API 후보를 심각도순으로 반환한다."""
    candidates: dict[str, list[SymbolInfo]] = {}
    for symbol in image.symbols + image.dynamic_symbols:
        canonical = _canonical_symbol(symbol.name)
        if canonical in _DANGEROUS:
            candidates.setdefault(canonical, []).append(symbol)

    call_sites, scan_truncated = _find_call_sites(
        image, set(candidates), max_instructions=max_instructions
    )
    findings: list[Finding] = []
    for canonical, symbols in candidates.items():
        category, severity, description = _DANGEROUS[canonical]
        calls = call_sites.get(canonical, [])
        raw_names = sorted({symbol.name for symbol in symbols if symbol.name})
        evidence = [f"Symbol detected: {name}" for name in raw_names]
        evidence.extend(f"Direct call at 0x{call.address:x}" for call in calls)
        if scan_truncated:
            evidence.append(
                f"Call-site scan stopped at the {max_instructions}-instruction safety limit"
            )
        findings.append(
            Finding(
                symbol=canonical,
                category=category,
                severity=severity,
                description=description,
                address=next((symbol.addr for symbol in symbols if symbol.addr), None),
                call_sites=calls,
                evidence=evidence,
                false_positive_factors=[
                    "A safe wrapper or validated length may dominate the call",
                    "Static argument recovery is incomplete",
                    "The imported symbol may be unreachable at runtime",
                ],
                confidence=0.78 if calls else 0.34,
            )
        )
    return sorted(
        findings, key=lambda finding: (_ORDER[finding.severity], finding.symbol)
    )


def _canonical_symbol(name: str) -> str:
    base = name.split("@")[0]
    if base.startswith("__") and base.endswith("_chk"):
        fortified = base[2:-4]
        fortified = _FORTIFIED_ALIASES.get(fortified, fortified)
        if fortified in _DANGEROUS:
            return fortified
    return base


def _find_call_sites(
    image: ElfImage,
    candidates: set[str],
    *,
    max_instructions: int,
) -> tuple[dict[str, list[CallSite]], bool]:
    if image.machine not in {"EM_386", "EM_X86_64"} or not candidates:
        return {}, False
    targets: dict[int, str] = {}
    for entry in analyze_got_plt(image).plt_entries:
        canonical = _canonical_symbol(entry.symbol)
        if entry.address is not None and canonical in candidates:
            targets[entry.address] = canonical
    for symbol in image.symbols + image.dynamic_symbols:
        canonical = _canonical_symbol(symbol.name)
        if symbol.addr and canonical in candidates:
            targets[symbol.addr] = canonical
    if not targets:
        return {}, False

    mode = CS_MODE_64 if image.bits == 64 else CS_MODE_32
    disassembler = Cs(CS_ARCH_X86, mode)
    functions = sorted(
        (
            symbol
            for symbol in image.symbols + image.dynamic_symbols
            if symbol.defined and symbol.stype == "STT_FUNC" and symbol.addr
        ),
        key=lambda symbol: symbol.addr,
    )
    output: dict[str, list[CallSite]] = {}
    remaining = max(1, max_instructions)
    scan_truncated = False
    for section in image.sections:
        if not section.executable or not section.size:
            continue
        blob = image.data[section.offset : section.offset + section.size]
        decoded = list(islice(disassembler.disasm(blob, section.addr), remaining + 1))
        if len(decoded) > remaining:
            instructions = decoded[:remaining]
            scan_truncated = True
        else:
            instructions = decoded
        remaining -= len(instructions)
        for index, instruction in enumerate(instructions):
            if instruction.mnemonic != "call":
                continue
            target = _parse_direct_target(instruction.op_str)
            if target is None or target not in targets:
                continue
            canonical = targets[target]
            before = instructions[max(0, index - 8) : index]
            # 버퍼 주소를 적재하는 ``lea reg, [rbp - N]`` 이 인자 setup 이 긴 호출
            # (예: read(fd, buf, n))에서는 call 4~5 명령 전에 올 수 있으므로,
            # surrounding window 를 argument 추정 window(-8)와 같게 넓힌다.
            window = instructions[max(0, index - 8) : min(len(instructions), index + 3)]
            arguments = (
                _estimate_x64_arguments(before)
                if image.bits == 64
                else _estimate_x86_arguments(before)
            )
            output.setdefault(canonical, []).append(
                CallSite(
                    address=int(instruction.address),
                    target_address=target,
                    function=_containing_function(functions, int(instruction.address)),
                    calling_convention=(
                        "sysv_amd64" if image.bits == 64 else "cdecl_i386"
                    ),
                    arguments=arguments,
                    surrounding_disassembly=[
                        f"0x{item.address:x}: {item.mnemonic} {item.op_str}".rstrip()
                        for item in window
                    ],
                )
            )
        if remaining <= 0:
            scan_truncated = True
            break
    return output, scan_truncated


def _parse_direct_target(operand: str) -> int | None:
    value = operand.strip()
    try:
        return int(value, 16) if value.startswith("0x") else None
    except ValueError:
        return None


def _estimate_x64_arguments(instructions: list) -> dict[str, str]:
    arguments: dict[str, str] = {}
    for canonical, aliases in _X64_ARGUMENT_REGISTERS:
        for instruction in reversed(instructions):
            operands = instruction.op_str.split(",", 1)
            destination = operands[0].strip().lower() if operands else ""
            if destination not in aliases:
                continue
            arguments[canonical] = (
                operands[1].strip()
                if len(operands) == 2
                else f"written by {instruction.mnemonic}"
            )
            break
    return arguments


def _estimate_x86_arguments(instructions: list) -> dict[str, str]:
    pushes = [
        instruction.op_str
        for instruction in instructions
        if instruction.mnemonic == "push"
    ]
    return {
        f"stack_arg_{index}": value for index, value in enumerate(reversed(pushes[-6:]))
    }


def _containing_function(functions: list[SymbolInfo], address: int) -> str | None:
    candidate: SymbolInfo | None = None
    for function in functions:
        if function.addr > address:
            break
        candidate = function
    if candidate is None:
        return None
    if candidate.size and address >= candidate.addr + candidate.size:
        return None
    return candidate.name or None
