"""서비스 계층 — 파싱/분석 코어를 직렬화 가능한 dict 로 감싼다."""

from __future__ import annotations

from dataclasses import asdict

from pwnable_lab.analyzer.checksec import run_checksec
from pwnable_lab.analyzer.disasm import disassemble
from pwnable_lab.analyzer.gadgets import find_gadgets, search_gadgets
from pwnable_lab.analyzer.got_plt import analyze_got_plt
from pwnable_lab.analyzer.strings import extract_strings
from pwnable_lab.analyzer.vuln_scan import scan_vulns
from pwnable_lab.config import Settings
from pwnable_lab.elf.parser import ElfImage, parse_elf


class AnalysisService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def image(self, data: bytes) -> ElfImage:
        return parse_elf(data)

    def info(self, data: bytes) -> dict:
        img = self.image(data)
        return {
            "bits": img.bits,
            "endian": img.endian,
            "machine": img.machine,
            "type": img.e_type,
            "entry": img.entry,
            "sections": [asdict(s) for s in img.sections],
            "symbols": [asdict(s) for s in img.symbols],
            "segments": [asdict(s) for s in img.segments],
            "dynamic_symbols": [asdict(s) for s in img.dynamic_symbols],
            "dynamic_tags": img.dynamic_tags,
        }

    def checksec(self, data: bytes) -> dict:
        return run_checksec(self.image(data)).as_dict()

    def vulns(self, data: bytes) -> list[dict]:
        return [asdict(f) for f in scan_vulns(self.image(data))]

    def gadgets(self, data: bytes, query: str | None = None) -> list[dict]:
        img = self.image(data)
        gadgets = find_gadgets(
            img,
            max_gadgets=self.settings.max_gadgets,
            max_depth=self.settings.max_gadget_depth,
        )
        if query:
            gadgets = search_gadgets(gadgets, query)
        return [
            {"address": g.address, "bytes_hex": g.bytes_hex,
             "instructions": g.instructions, "text": g.text}
            for g in gadgets
        ]

    def got_plt(self, data: bytes) -> dict:
        return analyze_got_plt(self.image(data)).as_dict()

    def strings(self, data: bytes, min_length: int = 4) -> list[dict]:
        strings = extract_strings(
            data, min_length=min_length, max_strings=self.settings.max_strings
        )
        return [asdict(s) for s in strings]

    def disassembly(self, data: bytes, address: int | None, count: int) -> list[dict]:
        insns = disassemble(
            self.image(data), address=address, count=count,
            max_instructions=self.settings.max_disasm_instructions,
        )
        return [
            {"address": i.address, "mnemonic": i.mnemonic,
             "op_str": i.op_str, "bytes_hex": i.bytes_hex, "text": i.text}
            for i in insns
        ]

    def hexdump(self, data: bytes, page: int) -> dict:
        size = self.settings.hex_page_size
        start = page * size
        chunk = data[start : start + size]
        rows = []
        for off in range(0, len(chunk), 16):
            row = chunk[off : off + 16]
            rows.append({
                "offset": start + off,
                "hex": " ".join(f"{b:02x}" for b in row),
                "ascii": "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in row),
            })
        return {
            "page": page,
            "page_size": size,
            "total_size": len(data),
            "total_pages": (len(data) + size - 1) // size,
            "rows": rows,
        }
