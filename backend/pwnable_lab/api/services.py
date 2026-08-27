"""서비스 계층 — 파싱/분석 코어를 직렬화 가능한 dict 로 감싼다."""

from __future__ import annotations

import hashlib
import logging
import os
import stat
import tempfile
from dataclasses import asdict, dataclass

from pwnable_lab.analyzer.checksec import run_checksec
from pwnable_lab.analyzer.control_flow import ControlFlowAnalyzer
from pwnable_lab.analyzer.core_dump import CoreLimits, analyze_core_dump
from pwnable_lab.analyzer.crash_log import Limits, analyze_crash_log
from pwnable_lab.analyzer.decompile import decompile_function
from pwnable_lab.analyzer.disasm import disassemble
from pwnable_lab.analyzer.entropy import raw_entropy_windows, shannon_entropy
from pwnable_lab.analyzer.gadgets import (
    GadgetFilter,
    filter_gadgets,
    scan_gadgets,
    simulate_chain,
)
from pwnable_lab.analyzer.ghidra import (
    GhidraError,
    decompile_with_ghidra,
    ghidra_available,
)
from pwnable_lab.analyzer.ghidra_insights import (
    OverflowInsight,
    best_overflow_offset,
    overflow_insights,
)
from pwnable_lab.analyzer.got_plt import analyze_got_plt
from pwnable_lab.analyzer.strategy import (
    analyze_strategy,
    execve_plan,
    find_ret_gadget,
    inject_confirmed_offset,
    is_pie,
    leak_plan,
    ret2system_plan,
    ret2system_plan32,
    ret2win_target,
)
from pwnable_lab.analyzer.strings import extract_strings
from pwnable_lab.analyzer.vuln_scan import scan_vulns
from pwnable_lab.config import Settings
from pwnable_lab.elf.parser import ElfImage, parse_elf
from pwnable_lab.errors import AnalysisError
from pwnable_lab.formats import ArtifactFormat, detect_format
from pwnable_lab.pe.analyzer import (
    disassemble_pe,
    disassemble_raw,
    pe_checksec,
    raw_checksec,
    scan_pe_imports,
)
from pwnable_lab.pe.parser import parse_pe
from pwnable_lab.sandbox import (
    SandboxLimits,
    auto_execve_core,
    auto_execve_in_container,
    auto_execve_pie_core,
    auto_execve_pie_in_container,
    auto_fmt_leak_pie_core,
    auto_fmt_leak_pie_in_container,
    auto_ret2libc_core,
    auto_ret2libc_in_container,
    auto_ret2system32_core,
    auto_ret2system32_in_container,
    auto_ret2system_core,
    auto_ret2system_in_container,
    auto_ret2system_pie_core,
    auto_ret2system_pie_in_container,
    auto_ret2win_pie_core,
    auto_ret2win_pie_in_container,
    confirm_offset_in_container,
    confirm_offset_in_process,
    require_isolation_marker,
    require_sandbox_enabled,
    verify_exploit_in_container,
    verify_exploit_in_process,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ArtifactInspection:
    format: ArtifactFormat
    machine: str
    bits: int
    verification: str
    evidence: list[str]


class AnalysisService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def inspect(self, data: bytes) -> ArtifactInspection:
        artifact_format = detect_format(data)
        if artifact_format is ArtifactFormat.ELF:
            elf_image = parse_elf(data)
            return ArtifactInspection(
                artifact_format,
                elf_image.machine,
                elf_image.bits,
                "verified",
                ["ELF magic and complete pyelftools structure validation passed"],
            )
        if artifact_format is ArtifactFormat.PE:
            pe_image = parse_pe(data)
            return ArtifactInspection(
                artifact_format,
                pe_image.machine,
                pe_image.bits,
                "verified",
                ["MZ, PE signature, optional header, and section table validated"],
            )
        return ArtifactInspection(
            artifact_format,
            "UNKNOWN",
            0,
            "unknown",
            ["Bytes passed the raw-binary heuristic; architecture was not inferred"],
        )

    def crash_log(self, text: str) -> dict:
        """Analyze bounded debugger text without executing an attached artifact."""

        return analyze_crash_log(
            text,
            limits=Limits(
                max_lines=self.settings.max_crash_log_lines,
                max_stack_entries=self.settings.max_crash_stack_entries,
            ),
        )

    def core_dump(self, data: bytes) -> dict:
        """Parse a bounded Linux ELF core without loading or executing its target."""

        return analyze_core_dump(
            data,
            limits=CoreLimits(
                max_notes=self.settings.max_core_notes,
                max_note_bytes=self.settings.max_core_note_bytes,
                max_stack_entries=self.settings.max_crash_stack_entries,
            ),
        )

    def image(self, data: bytes) -> ElfImage:
        """Compatibility helper for callers that explicitly require an ELF."""

        self._require_format(data, ArtifactFormat.ELF)
        return parse_elf(data)

    def info(self, data: bytes) -> dict:
        artifact_format = detect_format(data)
        if artifact_format is ArtifactFormat.PE:
            return self._pe_info(data)
        if artifact_format is ArtifactFormat.RAW:
            return self._raw_info(data)
        return self._elf_info(data)

    def elf_info(self, data: bytes) -> dict:
        self._require_format(data, ArtifactFormat.ELF)
        return self._elf_info(data)

    def pe_info(self, data: bytes) -> dict:
        self._require_format(data, ArtifactFormat.PE)
        return self._pe_info(data)

    def _elf_info(self, data: bytes) -> dict:
        img = parse_elf(data)
        return {
            "format": "ELF",
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
            "bits": img.bits,
            "endian": img.endian,
            "machine": img.machine,
            "type": img.e_type,
            "entry": img.entry,
            "sections": [asdict(s) for s in img.sections],
            "symbols": [asdict(s) for s in img.symbols],
            "segments": [asdict(s) for s in img.segments],
            "dynamic_symbols": [asdict(s) for s in img.dynamic_symbols],
            "imports": [asdict(s) for s in img.imports],
            "exports": [asdict(s) for s in img.exports],
            "dynamic_tags": img.dynamic_tags,
            "interpreter": img.interpreter,
            "needed_libraries": img.needed_libraries,
            "linked_libc": img.linked_libc,
            "linking": img.linking,
            "soname": img.soname,
            "rpath": img.rpath,
            "runpath": img.runpath,
            "build_id": img.build_id,
            "gnu_properties": img.gnu_properties,
            "relocation_count": len(img.relocations),
            "global_entropy": round(shannon_entropy(data), 4),
        }

    def _pe_info(self, data: bytes) -> dict:
        image = parse_pe(data)
        symbols = [self._pe_export_symbol(item) for item in image.exports]
        dynamic_symbols = [self._pe_import_symbol(item) for item in image.imports]
        sections = [asdict(section) for section in image.sections]
        segments = [self._pe_segment(section) for section in image.sections]
        return {
            "format": "PE",
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
            "bits": image.bits,
            "endian": "little",
            "machine": image.machine,
            "type": image.pe_type,
            "file_type": image.file_type,
            "entry": image.entry or None,
            "entry_rva": image.entry_rva,
            "image_base": image.image_base,
            "sections": sections,
            "segments": segments,
            "symbols": symbols,
            "dynamic_symbols": dynamic_symbols,
            "imports": [asdict(item) for item in image.imports],
            "exports": [asdict(item) for item in image.exports],
            "interpreter": None,
            "needed_libraries": image.needed_libraries,
            "linked_libc": None,
            "linking": "dynamic" if image.imports else "unknown",
            "soname": None,
            "rpath": [],
            "runpath": [],
            "build_id": None,
            "gnu_properties": {},
            "relocation_count": len(image.relocations),
            "subsystem": image.subsystem,
            "timestamp": image.timestamp,
            "dll_characteristics": image.dll_characteristics,
            "size_of_image": image.size_of_image,
            "global_entropy": round(shannon_entropy(data), 4),
        }

    def _raw_info(self, data: bytes) -> dict:
        return {
            "format": "RAW",
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
            "bits": 0,
            "endian": "unknown",
            "machine": "UNKNOWN",
            "type": "RAW",
            "entry": None,
            "sections": [],
            "segments": [],
            "symbols": [],
            "dynamic_symbols": [],
            "imports": [],
            "exports": [],
            "interpreter": None,
            "needed_libraries": [],
            "linked_libc": None,
            "linking": "unknown",
            "soname": None,
            "rpath": [],
            "runpath": [],
            "build_id": None,
            "gnu_properties": {},
            "relocation_count": 0,
            "global_entropy": round(shannon_entropy(data), 4),
            "analysis_limitations": [
                "Architecture, load address, entry point, and memory permissions are unknown",
                "Disassembly requires explicit user-supplied architecture and base address",
            ],
        }

    def checksec(self, data: bytes) -> dict:
        artifact_format = detect_format(data)
        if artifact_format is ArtifactFormat.ELF:
            result = run_checksec(parse_elf(data)).as_dict()
            result["format"] = "ELF"
            return result
        if artifact_format is ArtifactFormat.PE:
            return pe_checksec(parse_pe(data))
        return raw_checksec()

    def vulns(self, data: bytes) -> list[dict]:
        artifact_format = detect_format(data)
        if artifact_format is ArtifactFormat.PE:
            return scan_pe_imports(parse_pe(data))
        if artifact_format is ArtifactFormat.RAW:
            return []
        return [
            asdict(f)
            for f in scan_vulns(
                parse_elf(data),
                max_instructions=self.settings.max_disasm_instructions,
            )
        ]

    def exploit_strategy(self, data: bytes) -> dict:
        """checksec/vulns/함수/gadget 근거를 종합한 후보 exploit 경로."""

        self._require_format(data, ArtifactFormat.ELF, feature="Exploit strategy")
        return analyze_strategy(
            parse_elf(data),
            max_instructions=self.settings.max_disasm_instructions,
        )

    def confirm_offset(self, data: bytes, *, pattern_length: int | None = None) -> dict:
        """업로드 바이너리를 격리 러너로 실제 실행해 반환 주소 오프셋을 확정한다.

        정적 ``exploit_strategy`` 의 추정 오프셋과 달리, cyclic 패턴을 주입해
        관측된 크래시로부터 역산한 ``verified`` 오프셋을 돌려준다.

        .. warning::
           신뢰할 수 없는 바이너리를 **실행**한다. 기본 비활성이며
           ``PLAB_SANDBOX_EXECUTION_ENABLED=1`` + 격리 컨테이너 경계에서만
           사용해야 한다.
        """

        return self._run_offset_confirmation(
            data,
            pattern_length=pattern_length,
            feature="Dynamic offset confirmation",
        )

    def auto_exploit(self, data: bytes, *, pattern_length: int | None = None) -> dict:
        """정적 전략 + 동적 오프셋 확정을 결합한 exploit 초안 파이프라인.

        1. ``exploit_strategy`` 로 후보 경로와 pwntools 스켈레톤을 만든다(정적).
        2. 격리 러너로 반환 주소 오프셋을 실제 실행으로 확정한다(동적).
        3. 확정된 오프셋을 각 스켈레톤에 주입해 "실행 가능한" 초안으로 승격한다.
        4. ret2win 타깃(win 함수, non-PIE 절대주소)이 있으면 확정 오프셋으로
           payload 를 자동 구성해 익스가 실제로 먹히는지 검증한다(무입력).

        오프셋 확정에 실패하면 정적 스켈레톤을 그대로 두고 ``confirmation`` 에
        관측 근거를 담아 반환한다(예외 아님).
        """

        strategy = self.exploit_strategy(data)
        confirmation = self._run_offset_confirmation(
            data, pattern_length=pattern_length, feature="Auto-exploit"
        )
        verification: dict = {"attempted": False, "reason": "offset-unconfirmed"}
        if confirmation.get("confirmed") and confirmation.get("offset") is not None:
            offset = int(confirmation["offset"])
            strategy = inject_confirmed_offset(
                strategy, offset, method=confirmation.get("method")
            )
            verification = self._auto_verify(data, offset)
        return {
            "strategy": strategy,
            "confirmation": confirmation,
            "verification": verification,
        }

    def _auto_verify(self, data: bytes, offset: int) -> dict:
        """확정 오프셋으로 익스 기법을 순서대로 자동 시도한다(ret2win → ret2system → execve).

        각 시도는 격리 샌드박스에서 실제 payload 를 실행한다. 성공한 첫 기법을
        반환하고, 모두 실패하면 첫 시도를 대표로 두되 ``attempts`` 에 전 시도를
        요약한다. 시도할 기법이 하나도 없으면 ``attempted=false``.
        """

        image = parse_elf(data)
        bits = image.bits or 64
        if is_pie(image):
            return self._auto_verify_pie(data, offset, image, bits)
        attempts: list[dict] = []

        win = ret2win_target(image)
        if win is not None:
            attempts.append(self._try_ret2win(data, offset, image, win, bits))
            if attempts[-1]["succeeded"]:
                return self._with_attempts(attempts[-1], attempts)

        if ret2system_plan(image) is not None:
            attempts.append(self._auto_ret2system(data, offset))
            if attempts[-1]["succeeded"]:
                return self._with_attempts(attempts[-1], attempts)

        # system 이 없는(주로 정적 링크) 바이너리는 execve syscall ROP 로 시도한다.
        if execve_plan(image) is not None:
            attempts.append(self._auto_execve(data, offset))
            if attempts[-1]["succeeded"]:
                return self._with_attempts(attempts[-1], attempts)

        # i386(32-bit): cdecl ret2system(스택 인자, pop 가젯 불필요).
        if ret2system_plan32(image) is not None:
            attempts.append(self._auto_ret2system32(data, offset))
            if attempts[-1]["succeeded"]:
                return self._with_attempts(attempts[-1], attempts)

        if attempts:
            return self._with_attempts(attempts[0], attempts)
        return {"attempted": False, "reason": "no-technique"}

    @staticmethod
    def _with_attempts(chosen: dict, attempts: list[dict]) -> dict:
        out = dict(chosen)
        if len(attempts) > 1:
            out["attempts"] = [
                {k: a.get(k) for k in ("technique", "succeeded", "reason")}
                for a in attempts
            ]
        return out

    def _try_ret2win(
        self,
        data: bytes,
        offset: int,
        image,
        win: tuple[str, int],
        bits: int,
    ) -> dict:
        """직접 ret2win, 실패 시 amd64 정렬용 ret 가젯으로 한 번 재시도."""

        name, addr = win
        result = self.verify_exploit(data, offset=offset, target=addr, bits=bits)
        alignment = False
        if not result.get("succeeded") and bits == 64:
            ret = find_ret_gadget(image)
            if ret is not None:
                retry = self.verify_exploit(
                    data, offset=offset, target=ret, bits=bits, chain=[addr]
                )
                if retry.get("succeeded"):
                    result, alignment = retry, True
        return {
            "attempted": True,
            "technique": "ret2win",
            "target_name": name,
            "target_addr": addr,
            "target_addr_hex": f"0x{addr:x}",
            "alignment_ret_gadget": alignment,
            "succeeded": result.get("succeeded", False),
            "reason": result.get("reason"),
            "result": result,
        }

    def _auto_ret2system(self, data: bytes, offset: int) -> dict:
        """완전 자동 ret2system 을 executor 별로 위임한다(셸 획득까지 증명).

        오케스트레이션 전체가 공유 코어(`sandbox/ret2system.py`)이고 PTY 셸 증명이
        로컬 실행이라, container 는 컨테이너 안의 CLI `--auto-ret2system` 로,
        inprocess 는 temp 파일에 코어를 직접 돌려 **양쪽 모두 셸을 증명**한다.
        """

        if self.settings.sandbox_executor == "container":
            return auto_ret2system_in_container(
                data, offset=offset, settings=self.settings
            )
        require_isolation_marker(self.settings)
        limits = SandboxLimits(
            wall_seconds=self.settings.sandbox_wall_seconds,
            cpu_seconds=self.settings.sandbox_cpu_seconds,
            address_space_bytes=self.settings.sandbox_address_space_bytes,
        )
        path = self._materialize(data)
        try:
            return auto_ret2system_core(path, offset=offset, limits=limits)
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

    def _auto_ret2system32(self, data: bytes, offset: int) -> dict:
        """완전 자동 i386 ret2system 을 executor 별로 위임한다(셸 획득까지 증명).

        ``_auto_ret2system`` 과 동일 구조: container 는 컨테이너 안의 CLI
        ``--auto-ret2system32`` 로, inprocess 는 temp 파일에 코어를 직접 돌린다.
        """

        if self.settings.sandbox_executor == "container":
            return auto_ret2system32_in_container(
                data, offset=offset, settings=self.settings
            )
        require_isolation_marker(self.settings)
        limits = SandboxLimits(
            wall_seconds=self.settings.sandbox_wall_seconds,
            cpu_seconds=self.settings.sandbox_cpu_seconds,
            address_space_bytes=self.settings.sandbox_address_space_bytes,
        )
        path = self._materialize(data)
        try:
            return auto_ret2system32_core(path, offset=offset, limits=limits)
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

    def _auto_execve(self, data: bytes, offset: int) -> dict:
        """완전 자동 execve syscall ROP 를 executor 별로 위임한다(셸 획득까지 증명).

        ``_auto_ret2system`` 과 동일 구조: container 는 컨테이너 안의 CLI
        ``--auto-execve`` 로, inprocess 는 temp 파일에 코어를 직접 돌린다.
        """

        if self.settings.sandbox_executor == "container":
            return auto_execve_in_container(data, offset=offset, settings=self.settings)
        require_isolation_marker(self.settings)
        limits = SandboxLimits(
            wall_seconds=self.settings.sandbox_wall_seconds,
            cpu_seconds=self.settings.sandbox_cpu_seconds,
            address_space_bytes=self.settings.sandbox_address_space_bytes,
        )
        path = self._materialize(data)
        try:
            return auto_execve_core(path, offset=offset, limits=limits)
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

    def _auto_verify_pie(self, data: bytes, offset: int, image, bits: int) -> dict:
        """PIE 자동 익스: 로드 base 를 로컬 관측(ASLR-off)해 rebase 후 기법 시도.

        비 PIE 경로(``_auto_verify``)와 같은 순서로 ret2win → ret2system → execve 를
        시도하되, 모든 절대주소를 관측 base 로 rebase 한다(win 함수가 없어도
        ret2system/execve 로 셸 증명 가능). amd64 전용.
        """

        if bits != 64:
            return {"attempted": False, "reason": "pie-amd64-only"}
        attempts: list[dict] = []

        if ret2win_target(image) is not None:
            attempts.append(self._auto_ret2win_pie(data, offset))
            if attempts[-1].get("succeeded"):
                return self._with_attempts(attempts[-1], attempts)

        if ret2system_plan(image) is not None:
            attempts.append(self._auto_ret2system_pie(data, offset))
            if attempts[-1].get("succeeded"):
                return self._with_attempts(attempts[-1], attempts)

        # system 이 없는 PIE(주로 정적 링크)는 execve syscall ROP 로 시도한다.
        if execve_plan(image) is not None:
            attempts.append(self._auto_execve_pie(data, offset))
            if attempts[-1].get("succeeded"):
                return self._with_attempts(attempts[-1], attempts)

        if attempts:
            return self._with_attempts(attempts[0], attempts)
        return {"attempted": False, "reason": "pie-no-technique"}

    def _auto_ret2win_pie(self, data: bytes, offset: int) -> dict:
        """PIE 자동 ret2win 을 executor 별로 위임한다(base 관측→rebase→셸 증명).

        로드 base 관측(``resolve_pie_base``)과 ASLR-off 검증이 모두 실행 프로세스
        안에서 일어나야 하므로, container 는 컨테이너 안의 CLI 로, inprocess 는
        temp 파일에 코어를 직접 돌린다(ret2system 위임과 동일 구조).
        """

        if self.settings.sandbox_executor == "container":
            return auto_ret2win_pie_in_container(
                data, offset=offset, settings=self.settings
            )
        require_isolation_marker(self.settings)
        limits = SandboxLimits(
            wall_seconds=self.settings.sandbox_wall_seconds,
            cpu_seconds=self.settings.sandbox_cpu_seconds,
            address_space_bytes=self.settings.sandbox_address_space_bytes,
        )
        path = self._materialize(data)
        try:
            return auto_ret2win_pie_core(path, offset=offset, limits=limits)
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

    def _auto_ret2system_pie(self, data: bytes, offset: int) -> dict:
        """PIE 자동 ret2system 을 executor 별로 위임한다(base 관측→rebase→셸 증명).

        win 함수가 없는 PIE 를 위한 경로. ``_auto_ret2win_pie`` 와 동일 구조로
        container 는 CLI ``--auto-ret2system-pie`` 로, inprocess 는 코어를 직접 돌린다.
        """

        if self.settings.sandbox_executor == "container":
            return auto_ret2system_pie_in_container(
                data, offset=offset, settings=self.settings
            )
        require_isolation_marker(self.settings)
        limits = SandboxLimits(
            wall_seconds=self.settings.sandbox_wall_seconds,
            cpu_seconds=self.settings.sandbox_cpu_seconds,
            address_space_bytes=self.settings.sandbox_address_space_bytes,
        )
        path = self._materialize(data)
        try:
            return auto_ret2system_pie_core(path, offset=offset, limits=limits)
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

    def _auto_execve_pie(self, data: bytes, offset: int) -> dict:
        """PIE 자동 execve syscall ROP 를 executor 별로 위임한다(base 관측→rebase→셸 증명).

        ``system`` 이 없는 PIE 를 위한 경로. ``_auto_ret2system_pie`` 와 동일 구조로
        container 는 CLI ``--auto-execve-pie`` 로, inprocess 는 코어를 직접 돌린다.
        """

        if self.settings.sandbox_executor == "container":
            return auto_execve_pie_in_container(
                data, offset=offset, settings=self.settings
            )
        require_isolation_marker(self.settings)
        limits = SandboxLimits(
            wall_seconds=self.settings.sandbox_wall_seconds,
            cpu_seconds=self.settings.sandbox_cpu_seconds,
            address_space_bytes=self.settings.sandbox_address_space_bytes,
        )
        path = self._materialize(data)
        try:
            return auto_execve_pie_core(path, offset=offset, limits=limits)
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

    def verify_exploit(
        self,
        data: bytes,
        *,
        offset: int,
        target: int,
        bits: int | None = None,
        chain: list[int] | tuple[int, ...] = (),
        markers: list[str] | tuple[str, ...] = (),
    ) -> dict:
        """구성한 ret2win/ROP payload 를 격리 샌드박스에 주입해 익스 성공을 검증한다.

        ``payload = b'A'*offset + p{bits}(target) + Σ p{bits}(chain)`` 를 실제로
        보내, 크래시 없이 제어가 이전됐는지(또는 ``markers`` 가 stdout 에 나타나는지)
        로 판정한다. ``chain`` 으로 ret2system(pop rdi→/bin/sh→system) 같은 다단계
        ROP 나 정렬용 ret 가젯을 표현할 수 있다.
        """

        require_sandbox_enabled(self.settings)
        self._require_format(data, ArtifactFormat.ELF, feature="Exploit verification")
        resolved_bits = bits or (parse_elf(data).bits or 64)
        logger.warning(
            "sandbox: verifying exploit "
            "(executor=%s, offset=%d, target=0x%x, chain=%d)",
            self.settings.sandbox_executor,
            offset,
            target,
            len(chain),
        )
        executor = (
            verify_exploit_in_container
            if self.settings.sandbox_executor == "container"
            else verify_exploit_in_process
        )
        return executor(
            data,
            offset=offset,
            target=target,
            bits=resolved_bits,
            chain=chain,
            markers=markers,
            settings=self.settings,
        )

    def verify_leak(self, data: bytes, *, offset: int, bits: int | None = None) -> dict:
        """puts(puts@got) → exit 체인으로 런타임 libc 주소를 유출한다(amd64).

        ``puts`` 가 GOT 슬롯의 값(런타임 libc 주소)을 출력하고 ``exit`` 로 깨끗이
        종료해 stdio 버퍼를 flush 한다 → 유출 바이트를 stdout 에서 회수한다.
        ASLR 우회(libc base 계산)의 1단계 primitive.
        """

        require_sandbox_enabled(self.settings)
        self._require_format(data, ArtifactFormat.ELF, feature="Libc leak")
        image = parse_elf(data)
        plan = leak_plan(image)
        if plan is None:
            return {"attempted": False, "reason": "no-leak-plan"}
        resolved_bits = bits or image.bits or 64
        result = self.verify_exploit(
            data,
            offset=offset,
            target=plan["pop_rdi"],
            chain=[plan["got_target"], plan["puts_plt"], plan["exit_plt"]],
            bits=resolved_bits,
        )
        leaked = _parse_leaked_address(result)
        ok = leaked is not None and leaked > 0x1000
        return {
            "attempted": True,
            "technique": "libc-leak-puts",
            "got_target_hex": f"0x{plan['got_target']:x}",
            "leaked_addr": leaked,
            "leaked_hex": None if leaked is None else f"0x{leaked:x}",
            "succeeded": ok,
            "reason": "leaked" if ok else "no-leak",
            "result": result,
        }

    def auto_ret2libc(self, data: bytes, *, offset: int) -> dict:
        """완전 자동 2단계 ret2libc: leak → libc base 계산 → system("/bin/sh").

        1. `A*off + pop_rdi + puts@got + puts@plt + <재진입>` 로 런타임 puts 유출.
        2. `libc_base = leaked - puts_offset` (실행 환경의 libc 심볼 오프셋 사용).
        3. `A*off + pop_rdi + binsh + ret + system` 로 되쏘아 system 호출.

        libc 오프셋은 **실행이 일어나는 환경**의 libc 에서 해석하므로, container
        executor 에서는 컨테이너 안의 CLI(`--auto-ret2libc`)로 위임한다.
        """

        require_sandbox_enabled(self.settings)
        self._require_format(data, ArtifactFormat.ELF, feature="Auto ret2libc")
        logger.warning(
            "sandbox: auto ret2libc (executor=%s, offset=%d)",
            self.settings.sandbox_executor,
            offset,
        )
        if self.settings.sandbox_executor == "container":
            return auto_ret2libc_in_container(
                data, offset=offset, settings=self.settings
            )

        require_isolation_marker(self.settings)  # in-process 실행 지점 마커 확인
        limits = SandboxLimits(
            wall_seconds=self.settings.sandbox_wall_seconds,
            cpu_seconds=self.settings.sandbox_cpu_seconds,
            address_space_bytes=self.settings.sandbox_address_space_bytes,
        )
        path = self._materialize(data)
        try:
            return auto_ret2libc_core(path, offset=offset, limits=limits)
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

    def auto_fmt_leak_pie(self, data: bytes) -> dict:
        """PIE 포맷스트링 in-band leak 자동 익스: base 유출 → rebase ret2win → 셸.

        다른 PIE 경로(로컬 base 관측)와 달리 대상이 흘리는 포맷스트링으로 base 를
        런타임에 복원하므로 **ASLR 이 켜져 있어도 성립**하는 진짜 leak 이다. 오버플로
        오프셋과 leak 인자 위치를 모두 자체 확정하므로 offset 인자가 필요 없다.

        오프셋 확정·leak 캘리브레이션·2단계 셸 증명이 실행 프로세스 안에서 일어나야
        하므로 container executor 는 컨테이너 안의 CLI(`--auto-fmt-leak-pie`)로 위임한다.
        """

        require_sandbox_enabled(self.settings)
        self._require_format(data, ArtifactFormat.ELF, feature="Auto fmt-leak PIE")
        logger.warning(
            "sandbox: auto fmt-leak PIE (executor=%s)", self.settings.sandbox_executor
        )
        if self.settings.sandbox_executor == "container":
            return auto_fmt_leak_pie_in_container(data, settings=self.settings)

        require_isolation_marker(self.settings)
        limits = SandboxLimits(
            wall_seconds=self.settings.sandbox_wall_seconds,
            cpu_seconds=self.settings.sandbox_cpu_seconds,
            address_space_bytes=self.settings.sandbox_address_space_bytes,
        )
        path = self._materialize(data)
        try:
            return auto_fmt_leak_pie_core(path, limits=limits)
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

    @staticmethod
    def _materialize(data: bytes) -> str:
        fd, path = tempfile.mkstemp(prefix="plab-sbx-")
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.chmod(path, stat.S_IRWXU)
        return path

    def _run_offset_confirmation(
        self, data: bytes, *, pattern_length: int | None, feature: str
    ) -> dict:
        """게이트/포맷 검증 후 설정된 executor 로 오프셋 확정을 수행한다."""

        # 마스터 게이트(활성화 여부)는 항상 API 계층에서 검증 → 비활성 시 503.
        # 격리 마커는 "실제 실행이 일어나는 곳"에서 확인한다: in-process 는
        # executor 내부에서, container 는 컨테이너 안의 CLI 가 검증한다.
        require_sandbox_enabled(self.settings)
        self._require_format(data, ArtifactFormat.ELF, feature=feature)

        length = pattern_length or self.settings.sandbox_pattern_length
        logger.warning(
            "sandbox: confirming offset for untrusted binary "
            "(executor=%s, pattern_length=%d)",
            self.settings.sandbox_executor,
            length,
        )
        if self.settings.sandbox_executor == "container":
            return confirm_offset_in_container(
                data, pattern_length=length, settings=self.settings
            )
        return confirm_offset_in_process(
            data, pattern_length=length, settings=self.settings
        )

    def ghidra_available(self) -> bool:
        """Ghidra 디컴파일 백엔드가 활성이고 설치돼 있는지."""

        return self.settings.ghidra_enabled and ghidra_available(
            self.settings.ghidra_home, self.settings.java_home
        )

    def decompile_ghidra(self, data: bytes) -> dict:
        """Ghidra headless 로 바이너리 전체를 디컴파일한다(진짜 디컴파일러).

        기본 비활성(``PLAB_GHIDRA_ENABLED``). 미설치/비활성이면 규칙 기반 pseudo-C
        폴백을 쓰라는 신호로 ``{"available": False, ...}`` 를 반환하고, 실패하면
        같은 형태로 ``error`` 를 담는다(예외를 던지지 않아 UI 가 폴백하기 쉽다).
        Ghidra 는 바이너리를 실행하지 않고 정적 분석만 한다.
        """

        self._require_format(data, ArtifactFormat.ELF, feature="Ghidra decompile")
        if not self.settings.ghidra_enabled:
            return {"available": False, "reason": "ghidra-disabled"}
        if not ghidra_available(self.settings.ghidra_home, self.settings.java_home):
            return {"available": False, "reason": "ghidra-not-installed"}
        try:
            result = decompile_with_ghidra(
                data,
                max_functions=self.settings.ghidra_max_functions,
                timeout_seconds=self.settings.ghidra_timeout_seconds,
                ghidra_home=self.settings.ghidra_home,
                java_home=self.settings.java_home,
            )
        except GhidraError as exc:
            logger.warning("ghidra decompile 실패: %s", exc)
            return {"available": True, "succeeded": False, "error": str(exc)}
        result["available"] = True
        result["succeeded"] = True
        return result

    def analyze_ghidra(self, data: bytes) -> dict:
        """Ghidra 디컴파일을 vuln_scan/strategy 에 피드백한 통합 분석.

        비싼 디컴파일을 **한 번** 돌려 두 곳에 먹인다:

        * **vuln_scan 피드백**: Ghidra 가 복원한 버퍼 크기·스택 레이아웃으로 확정
          스택 오버플로를 도출(``overflow_insights``)하고, 정적 findings 중 같은
          함수의 오버플로 sink 를 ``ghidra_confirmed``/``ghidra_offset`` 으로 승격.
        * **strategy 피드백**: 확정 오버플로 오프셋을 :func:`inject_confirmed_offset`
          로 정적 strategy 스켈레톤에 주입(정적 휴리스틱이 -O2/스트립에서 실패해도
          진짜 버퍼 크기 기반 오프셋을 채운다).

        비활성/미설치/실패 시 ``{"available": False, ...}`` 로 폴백 신호를 준다.
        """

        self._require_format(data, ArtifactFormat.ELF, feature="Ghidra analysis")
        decompiled = self.decompile_ghidra(data)
        if not decompiled.get("available") or not decompiled.get("succeeded", True):
            return decompiled  # available:False 또는 succeeded:False 그대로 폴백

        insights = overflow_insights(decompiled)
        insight_dicts = [asdict(i) for i in insights]
        best_offset = best_overflow_offset(insights)

        image = parse_elf(data)
        # vuln_scan 피드백: 정적 finding 을 Ghidra 확정으로 승격.
        confirmed_by_func: dict[str, OverflowInsight] = {}
        for ins in insights:
            if ins.confirmed and (
                ins.function not in confirmed_by_func
                or ins.offset > confirmed_by_func[ins.function].offset
            ):
                confirmed_by_func[ins.function] = ins
        findings = [asdict(f) for f in scan_vulns(image)]
        for finding in findings:
            hit = None
            for call in finding.get("call_sites", []):
                fn = call.get("function")
                if fn and fn in confirmed_by_func:
                    hit = confirmed_by_func[fn]
                    break
            if hit is not None:
                finding["ghidra_confirmed"] = True
                finding["ghidra_offset"] = hit.offset
                finding["status"] = "confirmed"
                finding.setdefault("evidence", []).append("Ghidra: " + hit.evidence)

        # strategy 피드백: 확정 오프셋 주입.
        strategy = analyze_strategy(image)
        if best_offset is not None:
            strategy = inject_confirmed_offset(
                strategy,
                best_offset,
                method="ghidra-stack-frame",
                source="ghidra-static",
                verification="static-ghidra",
            )

        return {
            "available": True,
            "succeeded": True,
            "program": decompiled.get("program"),
            "language": decompiled.get("language"),
            "function_count": decompiled.get("function_count"),
            # 디컴파일 C 를 그대로 전달(같은 실행 결과 재사용 — Ghidra 재실행 없음).
            "functions": decompiled.get("functions", []),
            "overflow_insights": insight_dicts,
            "best_overflow_offset": best_offset,
            "vulnerabilities": findings,
            "strategy": strategy,
        }

    def pseudo_c(self, data: bytes, *, address: int) -> dict:
        """단일 함수의 규칙 기반 pseudo-C 초안."""

        analyzer = self._control_flow(data)
        detail = analyzer.function_detail(
            address,
            max_instructions=self.settings.max_disasm_instructions,
        )
        names = {addr: names[0] for addr, names in analyzer.symbols.items() if names}
        return decompile_function(detail, bits=analyzer.bits, names=names)

    def gadgets(
        self,
        data: bytes,
        *,
        filters: GadgetFilter,
        offset: int,
        limit: int,
    ) -> dict:
        self._require_format(data, ArtifactFormat.ELF, feature="ROP gadget scan")
        img = parse_elf(data)
        scan = scan_gadgets(
            img,
            max_gadgets=self.settings.max_gadgets,
            max_depth=self.settings.max_gadget_depth,
        )
        gadgets = filter_gadgets(
            scan.gadgets,
            filters,
            bits=img.bits,
            endian=img.endian,
        )
        result = _page(
            [gadget.as_dict() for gadget in gadgets], offset=offset, limit=limit
        )
        result.update(
            {
                "format": "ELF",
                "bits": img.bits,
                "status": "partially_completed" if scan.truncated else "completed",
                "verification": "verified",
                "quality_verification": "inferred",
                "position_independent": scan.position_independent,
                "image_base": scan.image_base,
                "scanned_gadgets": len(scan.gadgets),
                "executable_sections": scan.executable_sections,
                "filters": asdict(filters),
                "evidence": [
                    "Every result exactly decodes from file-backed executable ELF bytes",
                    "Register and memory access metadata comes from Capstone instruction detail",
                ],
                "limitations": [
                    "Scans ret, ret-imm, syscall, int 0x80, and indirect "
                    "jmp/call reg or [mem] (JOP/COP) terminators",
                    "Quality scores are ranking heuristics and do not prove runtime usability",
                ],
            }
        )
        return result

    def simulate_rop(self, data: bytes, *, items: list[dict], rsp_mod16: int) -> dict:
        self._require_format(data, ArtifactFormat.ELF, feature="ROP chain simulation")
        img = parse_elf(data)
        scan = scan_gadgets(
            img,
            max_gadgets=self.settings.max_gadgets,
            max_depth=self.settings.max_gadget_depth,
        )
        return simulate_chain(
            scan.gadgets,
            items,
            bits=img.bits,
            position_independent=scan.position_independent,
            initial_rsp_mod16=rsp_mod16,
        )

    def got_plt(self, data: bytes) -> dict:
        self._require_format(data, ArtifactFormat.ELF, feature="GOT/PLT analysis")
        return analyze_got_plt(parse_elf(data)).as_dict()

    def symbols(
        self,
        data: bytes,
        *,
        kind: str,
        offset: int,
        limit: int,
    ) -> dict:
        artifact_format = detect_format(data)
        if artifact_format is ArtifactFormat.PE:
            pe_image = parse_pe(data)
            if kind == "imports":
                pe_symbols = [self._pe_import_symbol(item) for item in pe_image.imports]
            elif kind in {"exports", "functions", "static"}:
                pe_symbols = [self._pe_export_symbol(item) for item in pe_image.exports]
            elif kind == "dynamic":
                pe_symbols = [self._pe_import_symbol(item) for item in pe_image.imports]
            else:
                pe_symbols = [
                    *[self._pe_export_symbol(item) for item in pe_image.exports],
                    *[self._pe_import_symbol(item) for item in pe_image.imports],
                ]
            return _page(pe_symbols, offset=offset, limit=limit)
        if artifact_format is ArtifactFormat.RAW:
            return _page([], offset=offset, limit=limit)
        elf_image = parse_elf(data)
        if kind == "static":
            elf_symbols = elf_image.symbols
        elif kind == "dynamic":
            elf_symbols = elf_image.dynamic_symbols
        elif kind == "imports":
            elf_symbols = elf_image.imports
        elif kind == "exports":
            elf_symbols = elf_image.exports
        elif kind == "functions":
            elf_symbols = [
                symbol
                for symbol in elf_image.symbols + elf_image.dynamic_symbols
                if symbol.defined and symbol.stype == "STT_FUNC"
            ]
        else:
            elf_symbols = elf_image.symbols + elf_image.dynamic_symbols
        normalized = [asdict(symbol) for symbol in elf_symbols]
        return _page(normalized, offset=offset, limit=limit)

    def functions(
        self,
        data: bytes,
        *,
        query: str | None,
        offset: int,
        limit: int,
    ) -> dict:
        analyzer = self._control_flow(data)
        functions, truncated = analyzer.functions(
            max_instructions=self.settings.max_disasm_instructions
        )
        normalized = [asdict(item) for item in functions]
        if query:
            needle = query.strip().lower()
            normalized = [
                item
                for item in normalized
                if needle in item["name"].lower()
                or any(needle in alias.lower() for alias in item["aliases"])
                or needle in f"0x{item['address']:x}"
            ]
        result = _page(normalized, offset=offset, limit=limit)
        result.update(
            {
                "format": analyzer.artifact_format,
                "status": "partially_completed" if truncated else "completed",
                "verification": "inferred",
                "evidence": [
                    "Function starts combine verified symbols/entry points and inferred direct-call targets",
                    "Function boundaries without a valid symbol size are inferred from the next start or region end",
                ],
            }
        )
        return result

    def function_detail(self, data: bytes, *, address: int) -> dict:
        return self._control_flow(data).function_detail(
            address,
            max_instructions=self.settings.max_disasm_instructions,
        )

    def cfg(self, data: bytes, *, address: int) -> dict:
        return self._control_flow(data).cfg(
            address,
            max_instructions=self.settings.max_disasm_instructions,
        )

    def xrefs(
        self,
        data: bytes,
        *,
        address: int | None,
        direction: str,
        kind: str,
        offset: int,
        limit: int,
    ) -> dict:
        analyzer = self._control_flow(data)
        xrefs, truncated = analyzer.xrefs(
            address=address,
            direction=direction,
            kind=kind,
            max_instructions=self.settings.max_disasm_instructions,
        )
        result = _page([asdict(item) for item in xrefs], offset=offset, limit=limit)
        result.update(
            {
                "format": analyzer.artifact_format,
                "direction": direction,
                "kind": kind,
                "status": "partially_completed" if truncated else "completed",
                "verification": "verified",
                "limitations": [
                    "Only direct branch immediates and x86 RIP-relative memory references are resolved"
                ],
            }
        )
        return result

    def relocations(self, data: bytes, *, offset: int, limit: int) -> dict:
        artifact_format = detect_format(data)
        if artifact_format is ArtifactFormat.PE:
            relocations = [asdict(item) for item in parse_pe(data).relocations]
        elif artifact_format is ArtifactFormat.ELF:
            relocations = [asdict(item) for item in parse_elf(data).relocations]
        else:
            relocations = []
        return _page(relocations, offset=offset, limit=limit)

    def got_entries(self, data: bytes, *, offset: int, limit: int) -> dict:
        self._require_format(data, ArtifactFormat.ELF, feature="GOT analysis")
        report = analyze_got_plt(parse_elf(data))
        result = report.as_dict()
        entries = result.pop("entries")
        result["entries"] = entries[offset : offset + limit]
        result["pagination"] = {
            "total": len(entries),
            "offset": offset,
            "limit": limit,
        }
        return result

    def plt_entries(self, data: bytes, *, offset: int, limit: int) -> dict:
        self._require_format(data, ArtifactFormat.ELF, feature="PLT analysis")
        report = analyze_got_plt(parse_elf(data))
        entries = [asdict(entry) for entry in report.plt_entries]
        return _page(entries, offset=offset, limit=limit)

    def libraries(self, data: bytes) -> dict:
        artifact_format = detect_format(data)
        if artifact_format is ArtifactFormat.PE:
            pe_image = parse_pe(data)
            return {
                "format": "PE",
                "linking": "dynamic" if pe_image.imports else "unknown",
                "interpreter": None,
                "needed": pe_image.needed_libraries,
                "linked_libc": None,
                "soname": None,
                "rpath": [],
                "runpath": [],
                "verification": "verified",
                "source": "PE import directory",
                "confidence": 1.0,
            }
        if artifact_format is ArtifactFormat.RAW:
            return {
                "format": "RAW",
                "linking": "unknown",
                "interpreter": None,
                "needed": [],
                "linked_libc": None,
                "soname": None,
                "rpath": [],
                "runpath": [],
                "verification": "unknown",
                "source": "No recognized loader metadata",
                "confidence": 1.0,
            }
        elf_image = parse_elf(data)
        return {
            "format": "ELF",
            "linking": elf_image.linking,
            "interpreter": elf_image.interpreter,
            "needed": elf_image.needed_libraries,
            "linked_libc": elf_image.linked_libc,
            "soname": elf_image.soname,
            "rpath": elf_image.rpath,
            "runpath": elf_image.runpath,
            "verification": "verified",
            "source": "ELF program headers and dynamic tags",
            "confidence": 1.0,
        }

    def analysis_summary(self, data: bytes, binary_id: str) -> dict:
        artifact_format = detect_format(data)
        info = self.info(data)
        checksec = self.checksec(data)
        summary_key = artifact_format.value.lower()
        summary = {
            "sha256": binary_id,
            "size": len(data),
            "format": artifact_format.value,
            "bits": info["bits"],
            "endian": info["endian"],
            "machine": info["machine"],
            "type": info["type"],
            "entry": info["entry"],
            "linking": info["linking"],
            "needed_libraries": info["needed_libraries"],
            "section_count": len(info["sections"]),
            "segment_count": len(info["segments"]),
            "symbol_count": len(info["symbols"]) + len(info["dynamic_symbols"]),
            "import_count": len(info.get("imports", [])),
            "export_count": len(info.get("exports", [])),
            "relocation_count": info["relocation_count"],
            "global_entropy": info["global_entropy"],
        }
        if artifact_format is ArtifactFormat.ELF:
            image = parse_elf(data)
            got_plt = analyze_got_plt(image)
            summary.update(
                {
                    "interpreter": image.interpreter,
                    "linked_libc": image.linked_libc,
                    "build_id": image.build_id,
                    "got_entry_count": len(got_plt.got_entries),
                    "plt_entry_count": len(got_plt.plt_entries),
                    "import_count": len(image.imports),
                    "export_count": len(image.exports),
                }
            )
        return {
            "verification": (
                "unknown" if artifact_format is ArtifactFormat.RAW else "verified"
            ),
            "source": (
                "raw byte heuristics"
                if artifact_format is ArtifactFormat.RAW
                else "validated static executable parser"
            ),
            "confidence": 0.55 if artifact_format is ArtifactFormat.RAW else 1.0,
            "format": artifact_format.value,
            summary_key: summary,
            "checksec": checksec,
        }

    def entropy(self, data: bytes) -> dict:
        artifact_format = detect_format(data)
        if artifact_format is ArtifactFormat.ELF:
            image = parse_elf(data)
            regions = [
                {
                    "name": section.name,
                    "offset": section.offset,
                    "size": section.size,
                    "entropy": round(
                        shannon_entropy(
                            data[section.offset : section.offset + section.size]
                        ),
                        4,
                    ),
                    "executable": section.executable,
                    "writable": section.writable,
                    "verification": "verified",
                }
                for section in image.sections
                if section.size
            ]
        elif artifact_format is ArtifactFormat.PE:
            regions = [
                {
                    "name": section.name,
                    "offset": section.offset,
                    "size": section.size,
                    "entropy": section.entropy,
                    "executable": section.executable,
                    "writable": section.writable,
                    "verification": "verified",
                }
                for section in parse_pe(data).sections
                if section.size
            ]
        else:
            regions = raw_entropy_windows(data)
        return {
            "format": artifact_format.value,
            "global_entropy": round(shannon_entropy(data), 4),
            "regions": regions,
            "interpretation": "Entropy is evidence only and never confirms packing by itself.",
            "verification": "verified",
        }

    def strings(self, data: bytes, min_length: int = 4) -> list[dict]:
        strings = extract_strings(
            data, min_length=min_length, max_strings=self.settings.max_strings
        )
        return [asdict(s) for s in strings]

    def disassembly(
        self,
        data: bytes,
        address: int | None,
        count: int,
        *,
        architecture: str | None = None,
        base_address: int = 0,
    ) -> list[dict]:
        artifact_format = detect_format(data)
        if artifact_format is ArtifactFormat.ELF:
            insns = disassemble(
                parse_elf(data),
                address=address,
                count=count,
                max_instructions=self.settings.max_disasm_instructions,
            )
        elif artifact_format is ArtifactFormat.PE:
            insns = disassemble_pe(
                parse_pe(data),
                address=address,
                count=count,
                max_instructions=self.settings.max_disasm_instructions,
            )
        else:
            insns = disassemble_raw(
                data,
                architecture=architecture,
                base_address=base_address,
                address=address,
                count=count,
                max_instructions=self.settings.max_disasm_instructions,
            )
        return [
            {
                "address": i.address,
                "mnemonic": i.mnemonic,
                "op_str": i.op_str,
                "bytes_hex": i.bytes_hex,
                "text": i.text,
            }
            for i in insns
        ]

    def hexdump(self, data: bytes, page: int) -> dict:
        size = self.settings.hex_page_size
        start = page * size
        chunk = data[start : start + size]
        rows = []
        for off in range(0, len(chunk), 16):
            row = chunk[off : off + 16]
            rows.append(
                {
                    "offset": start + off,
                    "hex": " ".join(f"{b:02x}" for b in row),
                    "ascii": "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in row),
                }
            )
        return {
            "page": page,
            "page_size": size,
            "total_size": len(data),
            "total_pages": (len(data) + size - 1) // size,
            "rows": rows,
        }

    def _control_flow(self, data: bytes) -> ControlFlowAnalyzer:
        artifact_format = detect_format(data)
        if artifact_format is ArtifactFormat.ELF:
            return ControlFlowAnalyzer.from_elf(parse_elf(data))
        if artifact_format is ArtifactFormat.PE:
            return ControlFlowAnalyzer.from_pe(parse_pe(data))
        raise AnalysisError(
            "Function boundaries, xrefs, and CFG are unavailable for raw artifacts "
            "without a verified loader map."
        )

    @staticmethod
    def _pe_import_symbol(item) -> dict:  # noqa: ANN001
        return {
            "name": item.name,
            "addr": item.address,
            "size": 0,
            "stype": "IMPORT",
            "binding": item.library,
            "section_index": "IAT",
            "visibility": "DEFAULT",
            "table": "imports",
            "defined": False,
            "library": item.library,
            "verification": item.verification,
        }

    @staticmethod
    def _pe_export_symbol(item) -> dict:  # noqa: ANN001
        return {
            "name": item.name,
            "addr": item.address,
            "size": 0,
            "stype": "EXPORT",
            "binding": "GLOBAL",
            "section_index": item.ordinal,
            "visibility": "DEFAULT",
            "table": "exports",
            "defined": True,
            "verification": item.verification,
        }

    @staticmethod
    def _pe_segment(section) -> dict:  # noqa: ANN001
        return {
            "ptype": f"SECTION:{section.name}",
            "offset": section.offset,
            "vaddr": section.addr,
            "filesz": section.size,
            "memsz": section.virtual_size,
            "flags": section.characteristics,
            "readable": section.readable,
            "writable": section.writable,
            "executable": section.executable,
        }

    @staticmethod
    def _require_format(
        data: bytes,
        expected: ArtifactFormat,
        *,
        feature: str | None = None,
    ) -> None:
        actual = detect_format(data)
        if actual is not expected:
            subject = feature or f"{expected.value} metadata"
            raise AnalysisError(
                f"{subject} is not available for {actual.value} artifacts."
            )


def _page(items: list[dict], *, offset: int, limit: int) -> dict:
    return {
        "items": items[offset : offset + limit],
        "total": len(items),
        "offset": offset,
        "limit": limit,
    }


def _parse_leaked_address(verification: dict) -> int | None:
    """leak 체인 실행 결과의 stdout(hex)에서 유출된 포인터를 복원한다.

    ``puts`` 는 GOT 슬롯 바이트를 null 까지 출력한 뒤 개행을 붙이므로, 첫 줄
    바이트를 리틀엔디언 정수로 해석한다. 유출이 없으면 None.
    """

    hexstr = verification.get("observation", {}).get("stdout_hex")
    if not hexstr:
        return None
    try:
        raw = bytes.fromhex(hexstr)
    except ValueError:
        return None
    line = raw.split(b"\n", 1)[0]
    if not line:
        return None
    return int.from_bytes(line[:8], "little")
