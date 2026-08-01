"""근거와 불확실성을 보존하는 ELF 보호 기법 분석."""

from __future__ import annotations

from dataclasses import asdict, dataclass

from pwnable_lab.elf.parser import ElfImage, SegmentInfo


@dataclass
class Protection:
    name: str
    state: str
    enabled: bool | None
    verification: str
    evidence: list[str]
    impact: str
    possible_strategies: list[str]
    confidence: float

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class Checksec:
    """Legacy summary fields plus detailed protection findings."""

    relro: str
    canary: bool
    nx: bool
    pie: str
    rpath: bool
    runpath: bool
    fortify: bool
    symbols_stripped: bool
    executable_stack: bool | None
    rwx_segments: list[str]
    static: bool
    cet: bool
    ibt: bool
    shadow_stack: bool
    protections: list[Protection]

    def as_dict(self) -> dict:
        return {
            "relro": self.relro,
            "canary": self.canary,
            "nx": self.nx,
            "pie": self.pie,
            "rpath": self.rpath,
            "runpath": self.runpath,
            "fortify": self.fortify,
            "stripped": self.symbols_stripped,
            "executable_stack": self.executable_stack,
            "rwx_segments": self.rwx_segments,
            "static": self.static,
            "cet": self.cet,
            "ibt": self.ibt,
            "shadow_stack": self.shadow_stack,
            "protections": [protection.as_dict() for protection in self.protections],
        }


_CANARY_SYMBOLS = {"__stack_chk_fail", "__stack_chk_guard", "__intel_security_cookie"}
_X86_FEATURE_IBT = 1
_X86_FEATURE_SHSTK = 2


def run_checksec(image: ElfImage) -> Checksec:
    seg_types = {segment.ptype for segment in image.segments}
    all_symbols = image.symbols + image.dynamic_symbols
    names = {symbol.name for symbol in all_symbols}
    protections: list[Protection] = []

    stack_segment = next(
        (segment for segment in image.segments if segment.ptype == "PT_GNU_STACK"),
        None,
    )
    nx, executable_stack, nx_detail = _analyze_nx(stack_segment)
    protections.append(nx_detail)
    protections.append(
        Protection(
            name="executable_stack",
            state=(
                "unknown"
                if executable_stack is None
                else "detected" if executable_stack else "not_detected"
            ),
            enabled=executable_stack,
            verification="unknown" if executable_stack is None else "verified",
            evidence=list(nx_detail.evidence),
            impact=(
                "The ELF requests execute permission for the process stack."
                if executable_stack
                else (
                    "The ELF does not request an executable stack."
                    if executable_stack is False
                    else "Effective stack execute permission requires runtime verification."
                )
            ),
            possible_strategies=[
                "Confirm effective stack permissions from process maps"
            ],
            confidence=nx_detail.confidence,
        )
    )

    has_relro = "PT_GNU_RELRO" in seg_types
    bind_now = _has_bind_now(image)
    if not has_relro:
        relro = "No"
        relro_state = "none"
        relro_evidence = ["PT_GNU_RELRO segment was not found"]
        relro_impact = "GOT entries may remain writable after relocation."
        relro_strategies = ["Validate whether a writable GOT entry is reachable"]
    elif bind_now:
        relro = "Full"
        relro_state = "full"
        relro_evidence = [
            "PT_GNU_RELRO segment is present",
            "Immediate binding is enabled by a dynamic flag or tag",
        ]
        relro_impact = "The loader makes the relocation region read-only after startup."
        relro_strategies = [
            "Prefer another writable control target instead of the GOT",
            "Use a leak-and-ROP strategy when control-flow primitives exist",
        ]
    else:
        relro = "Partial"
        relro_state = "partial"
        relro_evidence = [
            "PT_GNU_RELRO segment is present",
            "Immediate binding was not detected",
        ]
        relro_impact = "Some relocation data is protected, but lazy-binding GOT entries may remain writable."
        relro_strategies = ["Inspect individual GOT entry permissions at runtime"]
    protections.append(
        Protection(
            name="relro",
            state=relro_state,
            enabled=has_relro,
            verification="verified",
            evidence=relro_evidence,
            impact=relro_impact,
            possible_strategies=relro_strategies,
            confidence=1.0,
        )
    )

    canary = bool(names & _CANARY_SYMBOLS)
    canary_symbols = sorted(names & _CANARY_SYMBOLS)
    protections.append(
        Protection(
            name="stack_canary",
            state="detected" if canary else "not_detected",
            enabled=canary,
            verification="verified" if canary else "inferred",
            evidence=(
                [f"{symbol} symbol was detected" for symbol in canary_symbols]
                if canary
                else ["No known stack-canary support symbol was detected"]
            ),
            impact=(
                "Protected functions are likely to detect a corrupted stack frame before returning."
                if canary
                else "No binary-wide canary evidence was found; individual functions still require inspection."
            ),
            possible_strategies=(
                [
                    "Leak the canary before overwriting it",
                    "Avoid the protected stack slot",
                    "Target a non-stack corruption primitive",
                ]
                if canary
                else ["Verify the target function prologue before assuming no canary"]
            ),
            confidence=0.98 if canary else 0.82,
        )
    )

    pie, pie_detail = _analyze_pie(image, seg_types)
    protections.append(pie_detail)

    fortified_symbols = sorted(
        name for name in names if name.startswith("__") and name.endswith("_chk")
    )
    fortify = bool(fortified_symbols)
    protections.append(
        Protection(
            name="fortify",
            state="detected" if fortify else "not_detected",
            enabled=fortify,
            verification="verified" if fortify else "inferred",
            evidence=(
                [f"Fortified symbol detected: {name}" for name in fortified_symbols]
                if fortify
                else ["No __*_chk symbol was detected"]
            ),
            impact=(
                "Some libc calls include compiler-generated bounds checks."
                if fortify
                else "No fortified call site was identified from symbols alone."
            ),
            possible_strategies=[
                "Inspect the exact fortified call and its compiler-known object size"
            ],
            confidence=0.98 if fortify else 0.72,
        )
    )

    feature_bits = image.gnu_properties.get("GNU_PROPERTY_X86_FEATURE_1_AND", 0)
    ibt = bool(feature_bits & _X86_FEATURE_IBT)
    shadow_stack = bool(feature_bits & _X86_FEATURE_SHSTK)
    cet = ibt or shadow_stack
    protections.extend(_cet_protections(feature_bits, ibt, shadow_stack))

    protections.extend(_path_protections(image))

    rwx_segments = [
        f"{segment.ptype}@0x{segment.vaddr:x}"
        for segment in image.segments
        if segment.writable and segment.executable
    ]
    protections.append(
        Protection(
            name="rwx_segments",
            state="detected" if rwx_segments else "not_detected",
            enabled=bool(rwx_segments),
            verification="verified",
            evidence=(
                [f"Writable and executable segment: {item}" for item in rwx_segments]
                if rwx_segments
                else ["No program segment is both writable and executable"]
            ),
            impact=(
                "Writable executable memory can reduce the value of NX for that region."
                if rwx_segments
                else "No static W+X segment was found."
            ),
            possible_strategies=[
                "Confirm effective runtime permissions from memory maps"
            ],
            confidence=1.0,
        )
    )

    symbols_stripped = len(image.symbols) == 0
    protections.append(
        Protection(
            name="stripped",
            state="stripped" if symbols_stripped else "symbols_present",
            enabled=symbols_stripped,
            verification="verified",
            evidence=[
                (
                    ".symtab is absent or empty"
                    if symbols_stripped
                    else f"{len(image.symbols)} static symbol entries were parsed"
                )
            ],
            impact=(
                "Function discovery and semantic navigation require more inference."
                if symbols_stripped
                else "Static symbols can improve navigation but do not establish safety."
            ),
            possible_strategies=[
                "Use CFG, xrefs, and dynamic symbols for function recovery"
            ],
            confidence=1.0,
        )
    )

    static = image.linking == "static"
    protections.append(
        Protection(
            name="static_linking",
            state="static" if static else "dynamic",
            enabled=static,
            verification="verified",
            evidence=(
                ["No interpreter, dynamic section, or needed library was detected"]
                if static
                else [
                    f"Interpreter: {image.interpreter or 'none'}",
                    f"Needed libraries: {', '.join(image.needed_libraries) or 'none'}",
                ]
            ),
            impact=(
                "Library code is embedded and the gadget/search surface is larger."
                if static
                else "Runtime library versions and load bases affect address resolution."
            ),
            possible_strategies=[
                (
                    "Identify embedded libc behavior"
                    if static
                    else "Resolve runtime library bases"
                )
            ],
            confidence=1.0,
        )
    )

    return Checksec(
        relro=relro,
        canary=canary,
        nx=nx,
        pie=pie,
        rpath=bool(image.rpath),
        runpath=bool(image.runpath),
        fortify=fortify,
        symbols_stripped=symbols_stripped,
        executable_stack=executable_stack,
        rwx_segments=rwx_segments,
        static=static,
        cet=cet,
        ibt=ibt,
        shadow_stack=shadow_stack,
        protections=protections,
    )


def _analyze_nx(
    stack_segment: SegmentInfo | None,
) -> tuple[bool, bool | None, Protection]:
    if stack_segment is None:
        return (
            False,
            None,
            Protection(
                name="nx",
                state="unknown",
                enabled=None,
                verification="unknown",
                evidence=["PT_GNU_STACK segment is absent"],
                impact="Stack execute permission is platform-dependent without PT_GNU_STACK.",
                possible_strategies=["Verify effective stack permissions at runtime"],
                confidence=0.35,
            ),
        )
    enabled = not stack_segment.executable
    permissions = _segment_permissions(stack_segment)
    return (
        enabled,
        stack_segment.executable,
        Protection(
            name="nx",
            state="enabled" if enabled else "disabled",
            enabled=enabled,
            verification="verified",
            evidence=[f"PT_GNU_STACK permissions are {permissions}"],
            impact=(
                "Direct execution of shellcode from the stack is restricted."
                if enabled
                else "The ELF requests an executable stack."
            ),
            possible_strategies=(
                ["Use code-reuse techniques such as ROP or ret2libc"]
                if enabled
                else [
                    "Validate effective stack permissions before considering shellcode"
                ]
            ),
            confidence=1.0,
        ),
    )


def _analyze_pie(image: ElfImage, seg_types: set[str]) -> tuple[str, Protection]:
    if image.e_type != "ET_DYN":
        return (
            "No PIE",
            Protection(
                name="pie",
                state="disabled",
                enabled=False,
                verification="verified",
                evidence=[f"ELF type is {image.e_type}, not ET_DYN"],
                impact="Main executable code addresses are normally fixed across runs.",
                possible_strategies=["Use verified image-relative addresses"],
                confidence=1.0,
            ),
        )
    if "PT_INTERP" in seg_types:
        return (
            "PIE",
            Protection(
                name="pie",
                state="enabled",
                enabled=True,
                verification="verified",
                evidence=["ELF type is ET_DYN", "PT_INTERP marks an executable image"],
                impact="Executable code addresses depend on the randomized image base.",
                possible_strategies=[
                    "Obtain a PIE pointer leak and derive the image base"
                ],
                confidence=1.0,
            ),
        )
    if image.entry == 0:
        return (
            "DSO",
            Protection(
                name="pie",
                state="not_applicable",
                enabled=None,
                verification="verified",
                evidence=["ET_DYN object has no PT_INTERP and a zero entry point"],
                impact="This object is classified as a shared library rather than a PIE executable.",
                possible_strategies=[],
                confidence=0.98,
            ),
        )
    return (
        "PIE",
        Protection(
            name="pie",
            state="likely_enabled",
            enabled=True,
            verification="inferred",
            evidence=[
                "ELF type is ET_DYN",
                "Entry point is non-zero",
                "PT_INTERP is absent",
            ],
            impact="The image likely uses a relocatable executable base.",
            possible_strategies=[
                "Confirm load type and image base with runtime mappings"
            ],
            confidence=0.72,
        ),
    )


def _cet_protections(
    feature_bits: int, ibt: bool, shadow_stack: bool
) -> list[Protection]:
    source = (
        f"GNU_PROPERTY_X86_FEATURE_1_AND has value 0x{feature_bits:x}"
        if feature_bits
        else "GNU_PROPERTY_X86_FEATURE_1_AND was not detected"
    )
    return [
        Protection(
            name="cet",
            state="features_declared" if feature_bits else "not_detected",
            enabled=bool(feature_bits),
            verification="verified" if feature_bits else "inferred",
            evidence=[source],
            impact=(
                "CET feature declarations are present; the runtime decides effective enforcement."
                if feature_bits
                else "No static x86 CET feature declaration was identified."
            ),
            possible_strategies=[
                "Verify CPU, kernel, loader, and process CET state before treating it as enforced"
            ],
            confidence=1.0 if feature_bits else 0.8,
        ),
        Protection(
            name="ibt",
            state="declared" if ibt else "not_detected",
            enabled=ibt,
            verification="verified" if ibt else "inferred",
            evidence=[source],
            impact=(
                "The binary declares IBT compatibility; effective enforcement still depends on the runtime."
                if ibt
                else "No static IBT requirement was identified."
            ),
            possible_strategies=[
                "Restrict indirect targets to verified IBT-compatible entries"
            ],
            confidence=1.0 if ibt else 0.8,
        ),
        Protection(
            name="shadow_stack",
            state="declared" if shadow_stack else "not_detected",
            enabled=shadow_stack,
            verification="verified" if shadow_stack else "inferred",
            evidence=[source],
            impact=(
                "The binary declares Shadow Stack compatibility; runtime enforcement is not statically confirmed."
                if shadow_stack
                else "No static Shadow Stack requirement was identified."
            ),
            possible_strategies=[
                "Prefer non-return control targets when enforcement is active"
            ],
            confidence=1.0 if shadow_stack else 0.8,
        ),
    ]


def _path_protections(image: ElfImage) -> list[Protection]:
    output: list[Protection] = []
    for name, paths in (("rpath", image.rpath), ("runpath", image.runpath)):
        detected = bool(paths)
        output.append(
            Protection(
                name=name,
                state="detected" if detected else "not_detected",
                enabled=detected,
                verification="verified",
                evidence=(
                    [f"{name.upper()} entry: {path}" for path in paths]
                    if detected
                    else [f"DT_{name.upper()} was not found"]
                ),
                impact=(
                    "Runtime library search paths can influence dependency resolution."
                    if detected
                    else "No embedded runtime library search path was found."
                ),
                possible_strategies=[
                    "Review path writability and deployment trust boundaries"
                ],
                confidence=1.0,
            )
        )
    return output


def _segment_permissions(segment: SegmentInfo) -> str:
    return "".join(
        (
            "R" if segment.readable else "-",
            "W" if segment.writable else "-",
            "X" if segment.executable else "-",
        )
    )


def _has_bind_now(image: ElfImage) -> bool:
    return (
        "DT_BIND_NOW" in image.dynamic_tags
        or bool(image.dynamic_flags.get("DT_FLAGS", 0) & 0x8)
        or bool(image.dynamic_flags.get("DT_FLAGS_1", 0) & 0x1)
        or any(symbol.name == "__relro_full" for symbol in image.symbols)
    )
