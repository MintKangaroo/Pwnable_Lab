"""Bounded, non-executing analysis of textual debugger crash logs.

The parser intentionally accepts only evidence present in user-provided text.  It does
not invoke GDB, execute the attached artifact, or guess missing addresses.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from pwnable_lab.payload.cyclic import cyclic

ANALYZER_NAME = "text_crash_log"
ANALYZER_VERSION = "1.0.0"

_ANSI_RE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
_HEX = r"0x[0-9a-fA-F]+"
_REGISTER_NAMES = {
    "rax",
    "rbx",
    "rcx",
    "rdx",
    "rsi",
    "rdi",
    "rbp",
    "rsp",
    "rip",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
    "eax",
    "ebx",
    "ecx",
    "edx",
    "esi",
    "edi",
    "ebp",
    "esp",
    "eip",
    "eflags",
    "cs",
    "ss",
    "ds",
    "es",
    "fs",
    "gs",
    "pc",
    "sp",
}
_REGISTER_RE = re.compile(
    rf"(?i)(?<![\w])({'|'.join(sorted(_REGISTER_NAMES, key=len, reverse=True))})"
    rf"\s+(?:=\s*)?({_HEX})(?![0-9a-f])"
)
_SIGNAL_RE = re.compile(
    r"(?i)(?:received signal|terminated with signal|signal(?:ed)?(?: with)?|stopped reason[: ]+)\s*"
    r"(SIG[A-Z0-9]+)"
)
_FAULT_PATTERNS = (
    re.compile(rf"(?i)(?:fault(?:ing)? address|si_addr)\s*[:=]?\s*({_HEX})"),
    re.compile(rf"(?i)cannot access memory at address\s+({_HEX})"),
    re.compile(rf"(?i)segmentation fault(?: at)?\s+({_HEX})"),
)
_INSTRUCTION_RE = re.compile(
    rf"(?:=>|►|→)\s*({_HEX})(?:\s+<([^>]+)>)?\s*:?\s*(.*)", re.IGNORECASE
)
_PROC_MAP_RE = re.compile(
    r"^\s*([0-9a-fA-F]+)-([0-9a-fA-F]+)\s+([rwxps-]{4})\s+"
    r"([0-9a-fA-F]+)\s+\S+\s+\d+\s*(.*)$"
)
_GDB_MAP_RE = re.compile(
    rf"^\s*({_HEX})\s+({_HEX})\s+({_HEX})\s+({_HEX})\s+" r"([rwxps-]{3,5})\s*(.*)$",
    re.IGNORECASE,
)
_STACK_LINE_RE = re.compile(rf"^\s*({_HEX})(?:\s+<[^>]+>)?\s*:\s*(.*)$")
_HEX_VALUE_RE = re.compile(_HEX, re.IGNORECASE)


@dataclass(frozen=True)
class Limits:
    max_lines: int = 100_000
    max_line_length: int = 16_384
    max_stack_entries: int = 4096


def normalize_crash_log(text: str, limits: Limits) -> list[str]:
    """Strip terminal control sequences and bound parser work."""

    result: list[str] = []
    for raw_line in text.splitlines()[: limits.max_lines]:
        line = _ANSI_RE.sub("", raw_line[: limits.max_line_length])
        # Preserve tabs and printable text but prevent stored log/control injection.
        line = "".join(char for char in line if char in "\t" or char.isprintable())
        result.append(line)
    return result


def analyze_crash_log(text: str, *, limits: Limits | None = None) -> dict[str, Any]:
    limits = limits or Limits()
    lines = normalize_crash_log(text, limits)
    dialect = _detect_dialect(lines)
    registers = _parse_registers(lines)
    architecture, bits = _infer_architecture(registers)
    mappings = _parse_mappings(lines)
    stack = _parse_stack(
        lines, bits=bits, mappings=mappings, limit=limits.max_stack_entries
    )
    signal = _first_match(lines, _SIGNAL_RE, group=1)
    fault_address = _find_fault_address(lines)
    instruction = _parse_instruction(lines)

    ip_name = "rip" if "rip" in registers else "eip" if "eip" in registers else "pc"
    sp_name = "rsp" if "rsp" in registers else "esp" if "esp" in registers else "sp"
    bp_name = "rbp" if "rbp" in registers else "ebp" if "ebp" in registers else None
    cyclic_match = _find_probable_cyclic(registers, stack, bits)
    root_cause = _infer_root_cause(signal, fault_address, cyclic_match)

    parsed_evidence = sum(
        (
            bool(signal),
            bool(registers),
            bool(stack),
            bool(mappings),
            bool(instruction),
        )
    )
    status = "completed" if parsed_evidence >= 2 else "partially_completed"
    confidence = min(1.0, 0.2 + parsed_evidence * 0.15)
    warnings: list[str] = []
    if len(text.splitlines()) > limits.max_lines:
        warnings.append(f"Only the first {limits.max_lines} lines were analyzed.")
    if any(len(line) > limits.max_line_length for line in text.splitlines()):
        warnings.append(
            f"Lines longer than {limits.max_line_length} characters were truncated."
        )

    register_items = []
    for name, item in registers.items():
        register_items.append(
            {
                "name": name,
                "value": item["value"],
                "value_hex": hex(item["value"]),
                "classification": _classify_pointer(item["value"], mappings),
                "verification": "verified",
                "confidence": 1.0,
                "evidence": [f"Parsed directly from log line {item['line_number']}"],
            }
        )

    return {
        "analyzer_name": ANALYZER_NAME,
        "analyzer_version": ANALYZER_VERSION,
        "status": status,
        "error": None,
        "confidence": round(confidence, 2),
        "evidence": [
            f"Parsed {len(lines)} bounded text log lines without executing the target",
            f"Detected debugger dialect: {dialect}",
        ],
        "source": {"kind": "text_log", "dialect": dialect},
        "architecture": {
            "value": architecture,
            "bits": bits,
            "verification": "inferred" if architecture != "unknown" else "unknown",
            "confidence": 0.95 if architecture != "unknown" else 0.0,
            "evidence": ["Register names in the supplied log"],
        },
        "signal": _observed_value(signal, "Signal token in the supplied log"),
        "fault_address": _observed_address(
            fault_address, "Fault-address token in the supplied log"
        ),
        "instruction_pointer": _register_pointer(registers, ip_name),
        "stack_pointer": _register_pointer(registers, sp_name),
        "base_pointer": _register_pointer(registers, bp_name),
        "crash_instruction": instruction
        or {
            "address": None,
            "symbol": None,
            "instruction": None,
            "verification": "unknown",
            "confidence": 0.0,
            "evidence": [],
        },
        "registers": register_items,
        "stack": stack,
        "mappings": mappings,
        "probable_overflow_pattern": cyclic_match,
        "probable_root_cause": root_cause,
        "warnings": warnings,
        "limitations": [
            "This result is derived from user-provided text and has no live process provenance.",
            "Register, stack, and mapping completeness depends on the commands captured in the log.",
            "Canary and return-address labels are heuristic candidates, never confirmed values.",
        ],
    }


def _detect_dialect(lines: list[str]) -> str:
    joined = "\n".join(lines[:500]).lower()
    if "pwndbg>" in joined or "pwndbg" in joined or "►" in joined:
        return "pwndbg"
    if "gef➤" in joined or "gef>" in joined or "gef" in joined:
        return "gef"
    if "(gdb)" in joined or "program received signal" in joined:
        return "gdb"
    return "generic"


def _parse_registers(lines: list[str]) -> dict[str, dict[str, int]]:
    registers: dict[str, dict[str, int]] = {}
    for line_number, line in enumerate(lines, start=1):
        for match in _REGISTER_RE.finditer(line):
            name = match.group(1).lower()
            try:
                value = int(match.group(2), 16)
            except ValueError:
                continue
            registers.setdefault(name, {"value": value, "line_number": line_number})
    return registers


def _infer_architecture(registers: dict[str, dict[str, int]]) -> tuple[str, int | None]:
    if "rip" in registers or "rsp" in registers or "r15" in registers:
        return "x86_64", 64
    if "eip" in registers or "esp" in registers:
        return "x86", 32
    return "unknown", None


def _parse_mappings(lines: list[str]) -> list[dict[str, Any]]:
    mappings: list[dict[str, Any]] = []
    for line_number, line in enumerate(lines, start=1):
        proc_match = _PROC_MAP_RE.match(line)
        gdb_match = _GDB_MAP_RE.match(line)
        if proc_match:
            start, end, perms, offset, path = proc_match.groups()
        elif gdb_match:
            start, end, _size, offset, perms, path = gdb_match.groups()
            start = start[2:]
            end = end[2:]
            offset = offset[2:]
        else:
            continue
        start_value = int(start, 16)
        end_value = int(end, 16)
        if end_value <= start_value:
            continue
        clean_path = path.strip() or None
        normalized_perms = perms[:4].ljust(4, "-")
        mappings.append(
            {
                "start": start_value,
                "end": end_value,
                "start_hex": hex(start_value),
                "end_hex": hex(end_value),
                "size": end_value - start_value,
                "offset": int(offset, 16),
                "permissions": normalized_perms,
                "path": clean_path,
                "kind": _mapping_kind(clean_path, normalized_perms),
                "verification": "verified",
                "confidence": 1.0,
                "evidence": [f"Parsed directly from log line {line_number}"],
            }
        )
    mappings.sort(key=lambda item: item["start"])
    return mappings


def _mapping_kind(path: str | None, permissions: str) -> str:
    lowered = (path or "").lower()
    if "[stack" in lowered:
        return "stack"
    if lowered == "[heap]":
        return "heap"
    if "libc" in lowered:
        return "libc"
    if "ld-linux" in lowered or "ld-musl" in lowered or "/ld-" in lowered:
        return "loader"
    if not path or path.startswith("["):
        return "anonymous"
    if "x" in permissions:
        return "executable"
    return "mapped_file"


def _parse_stack(
    lines: list[str],
    *,
    bits: int | None,
    mappings: list[dict[str, Any]],
    limit: int,
) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    pointer_bytes = 4 if bits == 32 else 8
    stack_pointer = None
    for line in lines:
        match = _REGISTER_RE.search(line)
        if match and match.group(1).lower() in {"rsp", "esp", "sp"}:
            stack_pointer = int(match.group(2), 16)
            break

    for line_number, line in enumerate(lines, start=1):
        match = _STACK_LINE_RE.match(line)
        if not match:
            continue
        base = int(match.group(1), 16)
        values = [int(item, 16) for item in _HEX_VALUE_RE.findall(match.group(2))]
        for index, value in enumerate(values):
            if len(entries) >= limit:
                return entries
            address = base + index * pointer_bytes
            classification = _classify_pointer(value, mappings)
            labels: list[str] = []
            confidence = 1.0
            if classification["kind"] in {
                "executable",
                "libc",
                "loader",
            } and "x" in str(classification.get("permissions", "")):
                labels.append("return_address_candidate")
                confidence = 0.55
            if _is_canary_candidate(
                value, bits, address, stack_pointer, classification
            ):
                labels.append("canary_candidate")
                confidence = min(confidence, 0.35)
            entries.append(
                {
                    "address": address,
                    "address_hex": hex(address),
                    "value": value,
                    "value_hex": hex(value),
                    "offset_from_sp": (
                        address - stack_pointer if stack_pointer is not None else None
                    ),
                    "ascii": _integer_ascii(value, pointer_bytes),
                    "classification": classification,
                    "labels": labels,
                    "verification": "verified",
                    "interpretation_verification": (
                        "inferred"
                        if labels or classification["kind"] != "unmapped"
                        else "unknown"
                    ),
                    "confidence": confidence,
                    "evidence": [f"Value parsed from log line {line_number}"],
                }
            )
    return entries


def _is_canary_candidate(
    value: int,
    bits: int | None,
    address: int,
    stack_pointer: int | None,
    classification: dict[str, Any],
) -> bool:
    if bits != 64 or value == 0 or value & 0xFF or classification["kind"] != "unmapped":
        return False
    if stack_pointer is None or not 0 <= address - stack_pointer <= 0x400:
        return False
    return value.bit_length() >= 40


def _classify_pointer(value: int, mappings: list[dict[str, Any]]) -> dict[str, Any]:
    if value == 0:
        return {
            "kind": "null",
            "mapping": None,
            "permissions": None,
            "verification": "inferred",
            "confidence": 1.0,
        }
    for mapping in mappings:
        if mapping["start"] <= value < mapping["end"]:
            return {
                "kind": mapping["kind"],
                "mapping": mapping["path"],
                "permissions": mapping["permissions"],
                "offset": value - mapping["start"],
                "verification": "inferred",
                "confidence": 0.95,
            }
    return {
        "kind": "unmapped",
        "mapping": None,
        "permissions": None,
        "verification": "unknown",
        "confidence": 0.2,
    }


def _find_probable_cyclic(
    registers: dict[str, dict[str, int]], stack: list[dict[str, Any]], bits: int | None
) -> dict[str, Any]:
    candidates: list[tuple[str, int]] = []
    for name in ("rip", "eip", "pc", "rbp", "ebp"):
        if name in registers:
            candidates.append((name, registers[name]["value"]))
    for entry in stack[:256]:
        candidates.append((f"stack:{entry['address_hex']}", entry["value"]))

    width = 4 if bits == 32 else 8
    patterns = [(8, cyclic(65_536, n=8))] if width >= 8 else []
    patterns.append((4, cyclic(65_536, n=4)))
    for source, value in candidates:
        masked = value & ((1 << (width * 8)) - 1)
        raw = masked.to_bytes(width, "little", signed=False)
        for n, pattern in patterns:
            offset = pattern.find(raw[:n])
            if offset >= 0:
                return {
                    "status": "likely",
                    "offset": offset,
                    "subsequence_hex": raw[:n].hex(),
                    "pattern_width": n,
                    "source": source,
                    "verification": "verified",
                    "confidence": 0.99,
                    "evidence": [
                        f"Little-endian bytes from {source} match the bounded De Bruijn pattern at offset {offset}"
                    ],
                    "constraints": [
                        "The offset is valid only if the crashing input used the same alphabet and subsequence width."
                    ],
                }
    return {
        "status": "unknown",
        "offset": None,
        "subsequence_hex": None,
        "pattern_width": None,
        "source": None,
        "verification": "unknown",
        "confidence": 0.0,
        "evidence": [],
        "constraints": [],
    }


def _infer_root_cause(
    signal: str | None,
    fault_address: int | None,
    cyclic_match: dict[str, Any],
) -> dict[str, Any]:
    if cyclic_match["offset"] is not None and cyclic_match["source"] in {
        "rip",
        "eip",
        "pc",
    }:
        return {
            "type": "instruction_pointer_overwrite",
            "status": "likely",
            "summary": "A cyclic input pattern appears in the instruction pointer.",
            "verification": "inferred",
            "confidence": 0.96,
            "evidence": list(cyclic_match["evidence"]),
            "recommended_next_steps": [
                "Reproduce the crash with the same cyclic pattern in an isolated sandbox.",
                "Confirm the reported offset before building a return chain.",
            ],
        }
    if signal == "SIGSEGV" and fault_address is not None and fault_address < 0x1000:
        return {
            "type": "null_pointer_access",
            "status": "possible",
            "summary": "SIGSEGV occurred at a low fault address.",
            "verification": "inferred",
            "confidence": 0.62,
            "evidence": [f"Observed fault address {hex(fault_address)}"],
            "recommended_next_steps": [
                "Inspect the crash instruction and dereferenced operand."
            ],
        }
    if signal:
        return {
            "type": (
                "invalid_memory_access" if signal == "SIGSEGV" else "process_signal"
            ),
            "status": "possible",
            "summary": f"The supplied log reports {signal}; the root cause is not proven.",
            "verification": "inferred",
            "confidence": 0.35,
            "evidence": [f"Observed signal {signal}"],
            "recommended_next_steps": [
                "Collect the crash instruction, registers, stack, and mappings in an isolated sandbox."
            ],
        }
    return {
        "type": "unknown",
        "status": "possible",
        "summary": "The text does not contain enough evidence to infer a crash cause.",
        "verification": "unknown",
        "confidence": 0.0,
        "evidence": [],
        "recommended_next_steps": [
            "Include the signal, register dump, stack memory, and process mappings."
        ],
    }


def _first_match(
    lines: list[str], pattern: re.Pattern[str], *, group: int
) -> str | None:
    for line in lines:
        match = pattern.search(line)
        if match:
            return match.group(group).upper()
    return None


def _find_fault_address(lines: list[str]) -> int | None:
    for line in lines:
        for pattern in _FAULT_PATTERNS:
            match = pattern.search(line)
            if match:
                return int(match.group(1), 16)
    return None


def _parse_instruction(lines: list[str]) -> dict[str, Any] | None:
    for line_number, line in enumerate(lines, start=1):
        match = _INSTRUCTION_RE.search(line)
        if not match:
            continue
        return {
            "address": int(match.group(1), 16),
            "address_hex": hex(int(match.group(1), 16)),
            "symbol": match.group(2),
            "instruction": match.group(3).strip() or None,
            "verification": "verified",
            "confidence": 1.0,
            "evidence": [f"Parsed directly from log line {line_number}"],
        }
    return None


def _observed_value(value: str | None, evidence: str) -> dict[str, Any]:
    return {
        "value": value,
        "verification": "verified" if value else "unknown",
        "confidence": 1.0 if value else 0.0,
        "evidence": [evidence] if value else [],
    }


def _observed_address(value: int | None, evidence: str) -> dict[str, Any]:
    return {
        "value": value,
        "value_hex": hex(value) if value is not None else None,
        "verification": "verified" if value is not None else "unknown",
        "confidence": 1.0 if value is not None else 0.0,
        "evidence": [evidence] if value is not None else [],
    }


def _register_pointer(
    registers: dict[str, dict[str, int]], name: str | None
) -> dict[str, Any]:
    if not name or name not in registers:
        return _observed_address(None, "")
    item = registers[name]
    return {
        "register": name,
        "value": item["value"],
        "value_hex": hex(item["value"]),
        "verification": "verified",
        "confidence": 1.0,
        "evidence": [f"Parsed directly from log line {item['line_number']}"],
    }


def _integer_ascii(value: int, width: int) -> str:
    masked = value & ((1 << (width * 8)) - 1)
    raw = masked.to_bytes(width, "little", signed=False)
    return "".join(chr(byte) if 32 <= byte < 127 else "." for byte in raw)
