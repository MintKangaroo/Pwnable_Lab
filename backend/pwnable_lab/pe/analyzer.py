"""Evidence-based PE protections, imports, and x86 disassembly."""

from __future__ import annotations

from dataclasses import asdict

from capstone import (  # type: ignore[import-untyped]
    CS_ARCH_X86,
    CS_MODE_32,
    CS_MODE_64,
    Cs,
)

from pwnable_lab.analyzer.checksec import Protection
from pwnable_lab.analyzer.disasm import Instruction
from pwnable_lab.errors import AnalysisError
from pwnable_lab.pe.parser import PEImage

_HIGH_ENTROPY_VA = 0x0020
_DYNAMIC_BASE = 0x0040
_FORCE_INTEGRITY = 0x0080
_NX_COMPAT = 0x0100
_NO_SEH = 0x0400
_APPCONTAINER = 0x1000
_GUARD_CF = 0x4000

_DANGEROUS_IMPORTS: dict[str, tuple[str, str, str]] = {
    "gets": ("memory-corruption", "critical", "Unbounded input API imported."),
    "strcpy": ("memory-corruption", "high", "Destination size is not encoded."),
    "strcat": ("memory-corruption", "high", "Destination size is not encoded."),
    "sprintf": ("memory-corruption", "high", "Unbounded formatted write API."),
    "scanf": (
        "memory-corruption",
        "high",
        "Input conversion bounds require call-site review.",
    ),
    "memcpy": (
        "memory-corruption",
        "medium",
        "Copy safety depends on the recovered length.",
    ),
    "recv": ("file-input", "medium", "Network input reaches a caller-provided buffer."),
    "readfile": (
        "file-input",
        "medium",
        "File input reaches a caller-provided buffer.",
    ),
    "system": ("command-execution", "high", "Command interpreter API imported."),
    "winexec": ("command-execution", "high", "Process execution API imported."),
    "createprocessa": ("command-execution", "high", "Process creation API imported."),
    "createprocessw": ("command-execution", "high", "Process creation API imported."),
    "shellexecutea": ("command-execution", "high", "Shell execution API imported."),
    "shellexecutew": ("command-execution", "high", "Shell execution API imported."),
}


def pe_checksec(image: PEImage) -> dict:
    characteristics = image.dll_characteristics
    has_relocations = bool(image.relocations)
    dynamic_base = bool(characteristics & _DYNAMIC_BASE)
    aslr_enabled = dynamic_base and has_relocations
    nx = bool(characteristics & _NX_COMPAT)
    high_entropy = bool(characteristics & _HIGH_ENTROPY_VA)
    guard_cf = bool(characteristics & _GUARD_CF)
    force_integrity = bool(characteristics & _FORCE_INTEGRITY)
    app_container = bool(characteristics & _APPCONTAINER)
    no_seh = bool(characteristics & _NO_SEH)
    certificate_offset, certificate_size = image.data_directories.get(
        "security", (0, 0)
    )
    certificate_present = bool(certificate_offset and certificate_size)
    rwx = [f"{section.name}@0x{section.addr:x}" for section in image.rwx_sections]

    protections = [
        Protection(
            name="aslr",
            state=(
                "compatible"
                if aslr_enabled
                else "declared_without_relocations" if dynamic_base else "disabled"
            ),
            enabled=aslr_enabled,
            verification="verified",
            evidence=[
                f"IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE is {'set' if dynamic_base else 'not set'}",
                f"{len(image.relocations)} base relocation entries were parsed",
            ],
            impact=(
                "The preferred image base can be randomized by the Windows loader."
                if aslr_enabled
                else "A reliably relocatable image base was not established."
            ),
            possible_strategies=[
                "Use module-relative addresses after obtaining an image-base leak"
            ],
            confidence=1.0,
        ),
        Protection(
            name="dep",
            state="compatible" if nx else "not_declared",
            enabled=nx,
            verification="verified",
            evidence=[
                f"IMAGE_DLLCHARACTERISTICS_NX_COMPAT is {'set' if nx else 'not set'}"
            ],
            impact=(
                "The image declares Data Execution Prevention compatibility."
                if nx
                else "DEP compatibility is not declared by this image."
            ),
            possible_strategies=[
                "Verify effective process mitigation policy at runtime"
            ],
            confidence=1.0,
        ),
        _flag_protection(
            "high_entropy_va",
            high_entropy,
            "IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA",
            "The image requests a larger ASLR address range when the platform supports it.",
        ),
        _flag_protection(
            "control_flow_guard",
            guard_cf,
            "IMAGE_DLLCHARACTERISTICS_GUARD_CF",
            "CFG compatibility is declared; load-config metadata and runtime policy decide enforcement.",
        ),
        _flag_protection(
            "force_integrity",
            force_integrity,
            "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY",
            "The loader may require integrity checks under applicable policy.",
        ),
        _flag_protection(
            "app_container",
            app_container,
            "IMAGE_DLLCHARACTERISTICS_APPCONTAINER",
            "The image declares AppContainer compatibility, not that it is currently sandboxed.",
        ),
        _flag_protection(
            "no_seh",
            no_seh,
            "IMAGE_DLLCHARACTERISTICS_NO_SEH",
            "Structured exception handling is declared unavailable for this image.",
        ),
        Protection(
            name="authenticode",
            state=(
                "certificate_table_present" if certificate_present else "not_detected"
            ),
            enabled=certificate_present,
            verification="unknown" if certificate_present else "verified",
            evidence=[
                (
                    f"Security directory references {certificate_size} bytes at file offset 0x{certificate_offset:x}"
                    if certificate_present
                    else "PE security directory is empty"
                )
            ],
            impact=(
                "Certificate data exists, but signature validity and trust were not verified."
                if certificate_present
                else "No embedded Authenticode certificate table was detected."
            ),
            possible_strategies=[
                "Verify the signature and certificate chain with a trusted offline verifier"
            ],
            confidence=1.0 if not certificate_present else 0.5,
        ),
        Protection(
            name="rwx_sections",
            state="detected" if rwx else "not_detected",
            enabled=bool(rwx),
            verification="verified",
            evidence=(
                [f"Writable and executable section: {item}" for item in rwx]
                if rwx
                else ["No PE section is both writable and executable"]
            ),
            impact=(
                "Static writable-executable memory can weaken code/data separation."
                if rwx
                else "No static W+X section was found."
            ),
            possible_strategies=["Confirm effective section permissions after loading"],
            confidence=1.0,
        ),
    ]
    return {
        "format": "PE",
        "relro": "Not applicable",
        "canary": None,
        "nx": nx,
        "pie": "ASLR" if aslr_enabled else "No ASLR",
        "rpath": False,
        "runpath": False,
        "fortify": None,
        "stripped": None,
        "executable_stack": None,
        "rwx_segments": rwx,
        "static": False,
        "cet": None,
        "ibt": None,
        "shadow_stack": None,
        "protections": [asdict(item) for item in protections],
    }


def raw_checksec() -> dict:
    protection = Protection(
        name="loader_mitigations",
        state="unknown",
        enabled=None,
        verification="unknown",
        evidence=["Raw bytes do not contain a recognized executable loader header"],
        impact="NX, ASLR, stack protection, and loader policy cannot be derived from raw bytes.",
        possible_strategies=[
            "Provide the original executable container or runtime mapping metadata"
        ],
        confidence=1.0,
    )
    return {
        "format": "RAW",
        "relro": "Not applicable",
        "canary": None,
        "nx": None,
        "pie": "Unknown",
        "rpath": False,
        "runpath": False,
        "fortify": None,
        "stripped": None,
        "executable_stack": None,
        "rwx_segments": [],
        "static": None,
        "cet": None,
        "ibt": None,
        "shadow_stack": None,
        "protections": [asdict(protection)],
    }


def scan_pe_imports(image: PEImage) -> list[dict]:
    findings: list[dict] = []
    for item in image.imports:
        key = item.name.lower()
        if key not in _DANGEROUS_IMPORTS:
            continue
        category, severity, description = _DANGEROUS_IMPORTS[key]
        findings.append(
            {
                "symbol": item.name,
                "category": category,
                "severity": severity,
                "description": description,
                "status": "possible",
                "address": item.address,
                "call_sites": [],
                "evidence": [
                    f"Verified import {item.library}!{item.name} at IAT 0x{item.address:x}"
                ],
                "false_positive_factors": [
                    "An imported API may be unreachable or called with validated data",
                    "No call-site data flow was recovered for this PE import",
                ],
                "confidence": 0.4,
                "verification": "inferred",
            }
        )
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(findings, key=lambda item: (order[item["severity"]], item["symbol"]))


def disassemble_pe(
    image: PEImage,
    *,
    address: int | None,
    count: int,
    max_instructions: int,
) -> list[Instruction]:
    if image.machine not in {
        "IMAGE_FILE_MACHINE_I386",
        "IMAGE_FILE_MACHINE_AMD64",
    }:
        raise AnalysisError(
            f"PE disassembly currently supports x86/x86-64 only: {image.machine}"
        )
    if count > max_instructions:
        raise AnalysisError(
            f"Requested instruction count ({count}) exceeds limit ({max_instructions})."
        )
    start = address if address is not None else image.entry
    section = image.section_containing(start)
    if section is None or not section.executable:
        raise AnalysisError("Address is not inside an executable PE section.")
    delta = start - section.addr
    if delta >= section.size:
        raise AnalysisError("Address has no file-backed bytes in the PE section.")
    blob = image.data[section.offset + delta : section.offset + section.size]
    return _disassemble_x86(blob, start, image.bits, count)


def disassemble_raw(
    data: bytes,
    *,
    architecture: str | None,
    base_address: int,
    address: int | None,
    count: int,
    max_instructions: int,
) -> list[Instruction]:
    if architecture not in {"x86", "x86_64"}:
        raise AnalysisError(
            "Raw disassembly requires an explicit architecture: x86 or x86_64."
        )
    if count > max_instructions:
        raise AnalysisError(
            f"Requested instruction count ({count}) exceeds limit ({max_instructions})."
        )
    start = base_address if address is None else address
    offset = start - base_address
    if offset < 0 or offset >= len(data):
        raise AnalysisError(
            "Raw disassembly address is outside the uploaded byte range."
        )
    return _disassemble_x86(
        data[offset:], start, 64 if architecture == "x86_64" else 32, count
    )


def _disassemble_x86(
    blob: bytes, start: int, bits: int, count: int
) -> list[Instruction]:
    engine = Cs(CS_ARCH_X86, CS_MODE_64 if bits == 64 else CS_MODE_32)
    output: list[Instruction] = []
    for instruction in engine.disasm(blob, start):
        output.append(
            Instruction(
                int(instruction.address),
                instruction.mnemonic,
                instruction.op_str,
                instruction.bytes.hex(),
            )
        )
        if len(output) >= count:
            break
    return output


def _flag_protection(
    name: str, enabled: bool, flag_name: str, impact: str
) -> Protection:
    return Protection(
        name=name,
        state="declared" if enabled else "not_detected",
        enabled=enabled,
        verification="verified",
        evidence=[f"{flag_name} is {'set' if enabled else 'not set'}"],
        impact=impact if enabled else f"{flag_name} was not declared.",
        possible_strategies=["Confirm effective process mitigation policy at runtime"],
        confidence=1.0,
    )
