"""서비스 계층 — 파싱/분석 코어를 직렬화 가능한 dict 로 감싼다."""

from __future__ import annotations

import hashlib
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
        }

    def checksec(self, data: bytes) -> dict:
        return run_checksec(self.image(data)).as_dict()

    def vulns(self, data: bytes) -> list[dict]:
        return [
            asdict(f)
            for f in scan_vulns(
                self.image(data),
                max_instructions=self.settings.max_disasm_instructions,
            )
        ]

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
            {
                "address": g.address,
                "bytes_hex": g.bytes_hex,
                "instructions": g.instructions,
                "text": g.text,
            }
            for g in gadgets
        ]

    def got_plt(self, data: bytes) -> dict:
        return analyze_got_plt(self.image(data)).as_dict()

    def symbols(
        self,
        data: bytes,
        *,
        kind: str,
        offset: int,
        limit: int,
    ) -> dict:
        image = self.image(data)
        if kind == "static":
            symbols = image.symbols
        elif kind == "dynamic":
            symbols = image.dynamic_symbols
        elif kind == "imports":
            symbols = image.imports
        elif kind == "exports":
            symbols = image.exports
        elif kind == "functions":
            symbols = [
                symbol
                for symbol in image.symbols + image.dynamic_symbols
                if symbol.defined and symbol.stype == "STT_FUNC"
            ]
        else:
            symbols = image.symbols + image.dynamic_symbols
        normalized = [asdict(symbol) for symbol in symbols]
        return _page(normalized, offset=offset, limit=limit)

    def relocations(self, data: bytes, *, offset: int, limit: int) -> dict:
        relocations = [asdict(item) for item in self.image(data).relocations]
        return _page(relocations, offset=offset, limit=limit)

    def got_entries(self, data: bytes, *, offset: int, limit: int) -> dict:
        report = analyze_got_plt(self.image(data))
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
        report = analyze_got_plt(self.image(data))
        entries = [asdict(entry) for entry in report.plt_entries]
        return _page(entries, offset=offset, limit=limit)

    def libraries(self, data: bytes) -> dict:
        image = self.image(data)
        return {
            "linking": image.linking,
            "interpreter": image.interpreter,
            "needed": image.needed_libraries,
            "linked_libc": image.linked_libc,
            "soname": image.soname,
            "rpath": image.rpath,
            "runpath": image.runpath,
            "verification": "verified",
            "source": "ELF program headers and dynamic tags",
            "confidence": 1.0,
        }

    def analysis_summary(self, data: bytes, binary_id: str) -> dict:
        image = self.image(data)
        got_plt = analyze_got_plt(image)
        return {
            "verification": "verified",
            "source": "pyelftools normalized ELF parser",
            "confidence": 1.0,
            "elf": {
                "sha256": binary_id,
                "size": len(data),
                "bits": image.bits,
                "endian": image.endian,
                "machine": image.machine,
                "type": image.e_type,
                "entry": image.entry,
                "interpreter": image.interpreter,
                "linking": image.linking,
                "linked_libc": image.linked_libc,
                "needed_libraries": image.needed_libraries,
                "build_id": image.build_id,
                "section_count": len(image.sections),
                "segment_count": len(image.segments),
                "symbol_count": len(image.symbols) + len(image.dynamic_symbols),
                "import_count": len(image.imports),
                "export_count": len(image.exports),
                "relocation_count": len(image.relocations),
                "got_entry_count": len(got_plt.got_entries),
                "plt_entry_count": len(got_plt.plt_entries),
            },
            "checksec": run_checksec(image).as_dict(),
        }

    def strings(self, data: bytes, min_length: int = 4) -> list[dict]:
        strings = extract_strings(
            data, min_length=min_length, max_strings=self.settings.max_strings
        )
        return [asdict(s) for s in strings]

    def disassembly(self, data: bytes, address: int | None, count: int) -> list[dict]:
        insns = disassemble(
            self.image(data),
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


def _page(items: list[dict], *, offset: int, limit: int) -> dict:
    return {
        "items": items[offset : offset + limit],
        "total": len(items),
        "offset": offset,
        "limit": limit,
    }
