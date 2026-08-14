"""규칙 기반 pseudo-C 초안 생성기 (경량, 휴리스틱).

진짜 디컴파일러(Ghidra/angr)가 아니다. 선형 디스어셈블을 사람이 읽기 쉬운 C 유사
의사코드로 바꾸는 패턴 변환기다. 함수 프롤로그/에필로그, 호출과 인자, 문자열 리터럴,
비교/분기(if/goto), 후방 분기 기반 반복문(do/while 근사), 반환을 근사한다. 복잡한
데이터 흐름과 타입은 복원하지 않으며, 결과는 모두 ``inferred`` 로 표기한다.
"""

from __future__ import annotations

import re

# SysV amd64 정수 인자 레지스터 순서와 하위 별칭.
_ARG_REGS_64 = [
    ("rdi", {"rdi", "edi", "di", "dil"}),
    ("rsi", {"rsi", "esi", "si", "sil"}),
    ("rdx", {"rdx", "edx", "dx", "dl"}),
    ("rcx", {"rcx", "ecx", "cx", "cl"}),
    ("r8", {"r8", "r8d", "r8w", "r8b"}),
    ("r9", {"r9", "r9d", "r9w", "r9b"}),
]
_ALL_ARG_ALIASES = {alias for _, aliases in _ARG_REGS_64 for alias in aliases}
_PROLOGUE_EPILOGUE = {"push", "pop", "leave", "endbr64", "endbr32", "nop"}
_JCC_CONDITION = {
    "je": "==",
    "jz": "==",
    "jne": "!=",
    "jnz": "!=",
    "jg": ">",
    "jge": ">=",
    "jl": "<",
    "jle": "<=",
    "ja": "> (u)",
    "jae": ">= (u)",
    "jb": "< (u)",
    "jbe": "<= (u)",
    "js": "< 0",
    "jns": ">= 0",
}
_HEX = re.compile(r"^0x[0-9a-fA-F]+$")


def decompile_function(
    detail: dict,
    *,
    bits: int,
    names: dict[int, str] | None = None,
) -> dict:
    """함수 상세(instructions 포함)를 pseudo-C 초안 dict 로 변환한다."""

    names = names or {}
    instructions = detail.get("instructions", [])
    func_name = detail.get("name") or f"sub_{detail.get('address', 0):x}"
    frame_size = _frame_size(instructions)

    # 함수 내부로 향하는 분기 목표에 라벨을 부여한다.
    labels = _label_map(instructions)

    lines: list[str] = []
    lines.append(f"// pseudo-C (휴리스틱, inferred) — {func_name}")
    lines.append(
        f"// region 0x{detail.get('address', 0):x} .. 0x{detail.get('end', 0):x}"
    )
    signature = f"int {func_name}(void)"
    lines.append(signature + " {")
    if frame_size:
        lines.append(f"    char frame[0x{frame_size:x}];  // sub rsp, 0x{frame_size:x}")

    body = _emit_body(instructions, bits, names, labels)
    lines.extend("    " + line for line in body)
    lines.append("}")

    return {
        "format": detail.get("format", "ELF"),
        "name": func_name,
        "address": detail.get("address", 0),
        "end": detail.get("end", 0),
        "signature": signature,
        "frame_size": frame_size,
        "pseudocode": "\n".join(lines),
        "line_count": len(lines),
        "verification": "inferred",
        "confidence": 0.4,
        "truncated": bool(detail.get("truncated")),
        "notes": [
            "이것은 진짜 디컴파일이 아니라 어셈블리의 규칙 기반 근사입니다.",
            "인자 개수/타입, 지역변수, 반복문 구조는 정확하지 않을 수 있습니다.",
            "반복문은 후방 분기를 do/while 로 근사하며, while/for 원형은 복원하지 않습니다.",
            "호출 인자는 직전 레지스터 설정만 보고 추정합니다.",
        ],
        "disassembly_verification": "verified",
    }


def _frame_size(instructions: list[dict]) -> int:
    for insn in instructions[:12]:
        if insn.get("mnemonic") == "sub":
            ops = insn.get("op_str", "").split(",")
            if len(ops) == 2 and ops[0].strip() in {"rsp", "esp"}:
                value = ops[1].strip()
                try:
                    return int(value, 0)
                except ValueError:
                    return 0
    return 0


def _label_map(instructions: list[dict]) -> dict[int, str]:
    addresses = {insn.get("address") for insn in instructions}
    labels: dict[int, str] = {}
    for insn in instructions:
        if insn.get("is_jump") and insn.get("target") in addresses:
            target = insn["target"]
            labels[target] = f"loc_{target:x}"
    return labels


def _loop_headers(instructions: list[dict]) -> set[int]:
    """후방 분기(target < 분기 주소)의 목표를 루프 헤더로 본다."""
    addresses = {insn.get("address") for insn in instructions}
    headers: set[int] = set()
    for insn in instructions:
        if not insn.get("is_jump"):
            continue
        target = insn.get("target")
        if not isinstance(target, int):
            continue
        if target < insn.get("address", 0) and target in addresses:
            headers.add(target)
    return headers


def _emit_body(
    instructions: list[dict],
    bits: int,
    names: dict[int, str],
    labels: dict[int, str],
) -> list[str]:
    out: list[str] = []
    # 인자 레지스터 → 마지막으로 대입된 표현식(간단한 블록 내 추적).
    reg_expr: dict[str, str] = {}
    loop_headers = _loop_headers(instructions)
    loop_stack: list[int] = []  # 열려 있는 do{ 루프 헤더 주소 스택.
    indent = 0

    def reset_regs() -> None:
        reg_expr.clear()

    def emit(text: str) -> None:
        out.append(("    " * indent + text) if text else "")

    for insn in instructions:
        address = insn.get("address", 0)
        mnem = insn.get("mnemonic", "")
        op_str = insn.get("op_str", "")
        target = insn.get("target")

        # 루프 헤더 주소에 도달하면 do{ 를 열고 들여쓴다.
        if address in loop_headers and address not in loop_stack:
            emit("do {")
            loop_stack.append(address)
            indent += 1

        # 분기 목표면 라벨을 먼저 출력(구조화되지 않은 goto 참조 보존).
        if address in labels:
            emit(f"{labels[address]}:")

        # 후방 분기가 현재 열린 루프의 헤더를 정확히 가리키면 } while 로 닫는다.
        is_backward = isinstance(target, int) and target < address
        closes_loop = (
            is_backward
            and loop_stack
            and target == loop_stack[-1]
            and (mnem in _JCC_CONDITION or mnem == "jmp")
        )
        if closes_loop:
            indent = max(indent - 1, 0)
            loop_stack.pop()
            if mnem == "jmp":
                emit("} while (1);  // jmp (loop back-edge)")
            else:
                emit(f"}} while (cond {_JCC_CONDITION[mnem]});  // {mnem}")
            reset_regs()
            continue

        if mnem == "call":
            emit(_render_call(insn, bits, names, reg_expr))
            reset_regs()
            continue

        if mnem in ("mov", "lea", "movzx", "movsx"):
            _track_assignment(mnem, op_str, reg_expr)
            # 대입 자체도 흐름 이해를 위해 남기되 아는 레지스터만.
            continue

        if mnem == "xor":
            ops = [o.strip() for o in op_str.split(",")]
            if len(ops) == 2 and ops[0] == ops[1]:
                reg_expr[_canonical(ops[0])] = "0"
            continue

        if mnem in _JCC_CONDITION:
            emit(
                f"if (cond {_JCC_CONDITION[mnem]}) goto "
                f"{_branch_label(insn, labels, op_str)};  // {mnem}"
            )
            reset_regs()
            continue

        if mnem == "cmp" or mnem == "test":
            emit(f"// {mnem} {op_str}")
            continue

        if mnem == "jmp":
            emit(f"goto {_branch_label(insn, labels, op_str)};")
            reset_regs()
            continue

        if mnem == "ret":
            emit("return eax;  // ret")
            continue

        if mnem in _PROLOGUE_EPILOGUE:
            continue

        if mnem in ("add", "sub", "and", "or", "imul", "shl", "shr", "inc", "dec"):
            # 스택 프레임 조정(sub/add rsp)은 이미 frame[] 로 표현했으므로 생략.
            if op_str.split(",", 1)[0].strip() in {"rsp", "esp"}:
                continue
            emit(f"// {mnem} {op_str}".rstrip())
            continue

        # 그 외는 원본 명령을 주석으로 보존.
        emit(f"// 0x{address:x}: {mnem} {op_str}".rstrip())

    # 닫지 못한 루프(irreducible/겹침)는 괄호 균형을 위해 마지막에 닫는다.
    while loop_stack:
        loop_stack.pop()
        indent = max(indent - 1, 0)
        emit("}  // loop end (구조 추정 불완전)")

    if not out:
        out.append("// (본문 명령이 없습니다)")
    return out


def _branch_label(insn: dict, labels: dict[int, str], op_str: str) -> str:
    target = insn.get("target")
    if isinstance(target, int):
        return labels.get(target, f"0x{target:x}")
    return op_str or "?"


def _render_call(
    insn: dict,
    bits: int,
    names: dict[int, str],
    reg_expr: dict[str, str],
) -> str:
    target = insn.get("target")
    callee: str | None = None
    if isinstance(target, int):
        callee = names.get(target)
    if not callee:
        op = insn.get("op_str", "").strip()
        callee = f"sub_{target:x}" if isinstance(target, int) else (op or "func")

    args: list[str] = []
    if bits == 64:
        for canonical, _ in _ARG_REGS_64:
            if canonical in reg_expr:
                args.append(reg_expr[canonical])
            else:
                break
    arg_text = ", ".join(args)
    return f"{callee}({arg_text});"


def _track_assignment(mnem: str, op_str: str, reg_expr: dict[str, str]) -> None:
    ops = [o.strip() for o in op_str.split(",", 1)]
    if len(ops) != 2:
        return
    dest = _canonical(ops[0])
    # 인자 레지스터로 정규화되는 대상만 추적한다(잡음 감소).
    if dest not in {canonical for canonical, _ in _ARG_REGS_64}:
        return
    reg_expr[dest] = _render_source(mnem, ops[1].strip())


def _render_source(mnem: str, src: str) -> str:
    if _HEX.match(src):
        return src
    if src.isdigit():
        return src
    if src.startswith("[") and "rip" in src:
        return "&data"  # RIP 상대 → 전역 데이터/문자열 근사
    if src.startswith("["):
        return f"*({src})"
    return src


def _canonical(reg: str) -> str:
    reg = reg.strip().lower()
    for canonical, aliases in _ARG_REGS_64:
        if reg in aliases:
            return canonical
    return reg
