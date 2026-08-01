"""Bounded, dependency-free PE32/PE32+ metadata parser.

The parser never loads or executes the image. It intentionally covers the structural
metadata needed by the control plane while rejecting truncated table references.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from pwnable_lab.analyzer.entropy import shannon_entropy
from pwnable_lab.errors import ParseError, UnsupportedFormatError

_MACHINE_NAMES = {
    0x014C: "IMAGE_FILE_MACHINE_I386",
    0x01C0: "IMAGE_FILE_MACHINE_ARM",
    0x01C4: "IMAGE_FILE_MACHINE_ARMNT",
    0x8664: "IMAGE_FILE_MACHINE_AMD64",
    0xAA64: "IMAGE_FILE_MACHINE_ARM64",
}
_SUBSYSTEM_NAMES = {
    1: "NATIVE",
    2: "WINDOWS_GUI",
    3: "WINDOWS_CUI",
    7: "POSIX_CUI",
    9: "WINDOWS_CE_GUI",
    10: "EFI_APPLICATION",
    11: "EFI_BOOT_SERVICE_DRIVER",
    12: "EFI_RUNTIME_DRIVER",
    14: "XBOX",
    16: "WINDOWS_BOOT_APPLICATION",
}
_RELOCATION_NAMES = {
    0: "ABSOLUTE",
    1: "HIGH",
    2: "LOW",
    3: "HIGHLOW",
    4: "HIGHADJ",
    5: "MIPS_JMPADDR_OR_ARM_MOV32",
    10: "DIR64",
}
_MAX_SECTIONS = 96
_MAX_IMPORTS = 20_000
_MAX_EXPORTS = 20_000
_MAX_RELOCATIONS = 200_000


@dataclass
class PESectionInfo:
    name: str
    rva: int
    addr: int
    virtual_size: int
    offset: int
    size: int
    characteristics: int
    readable: bool
    writable: bool
    executable: bool
    entropy: float


@dataclass
class PEImportInfo:
    name: str
    library: str
    address: int
    rva: int
    ordinal: int | None
    hint: int | None
    verification: str = "verified"


@dataclass
class PEExportInfo:
    name: str
    address: int
    rva: int
    ordinal: int
    verification: str = "verified"


@dataclass
class PERelocationInfo:
    address: int
    rva: int
    page_rva: int
    relocation_type: str
    relocation_type_id: int
    verification: str = "verified"


@dataclass
class PEImage:
    data: bytes = field(repr=False)
    machine: str = ""
    machine_id: int = 0
    bits: int = 0
    pe_type: str = ""
    file_type: str = ""
    timestamp: int = 0
    characteristics: int = 0
    dll_characteristics: int = 0
    image_base: int = 0
    entry_rva: int = 0
    entry: int = 0
    section_alignment: int = 0
    file_alignment: int = 0
    size_of_image: int = 0
    size_of_headers: int = 0
    subsystem: str = "UNKNOWN"
    sections: list[PESectionInfo] = field(default_factory=list)
    imports: list[PEImportInfo] = field(default_factory=list)
    exports: list[PEExportInfo] = field(default_factory=list)
    relocations: list[PERelocationInfo] = field(default_factory=list)
    data_directories: dict[str, tuple[int, int]] = field(default_factory=dict)

    @property
    def needed_libraries(self) -> list[str]:
        return sorted({item.library for item in self.imports}, key=str.lower)

    @property
    def rwx_sections(self) -> list[PESectionInfo]:
        return [
            section
            for section in self.sections
            if section.writable and section.executable
        ]

    def section_containing(self, address: int) -> PESectionInfo | None:
        return next(
            (
                section
                for section in self.sections
                if section.addr
                <= address
                < section.addr + max(section.virtual_size, section.size)
            ),
            None,
        )


def parse_pe(data: bytes) -> PEImage:
    if not data.startswith(b"MZ"):
        raise UnsupportedFormatError("Windows PE DOS signature(MZ)가 아닙니다.")
    if len(data) < 0x40:
        raise ParseError("잘린 DOS 헤더입니다.")
    pe_offset = _unpack_from("<I", data, 0x3C)[0]
    if pe_offset < 0x40 or pe_offset + 24 > len(data):
        raise ParseError("PE 헤더 오프셋이 파일 범위를 벗어났습니다.")
    if data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        raise ParseError("PE signature가 없거나 손상되었습니다.")

    coff = _unpack_from("<HHIIIHH", data, pe_offset + 4)
    machine_id, section_count, timestamp, _, _, optional_size, characteristics = coff
    if section_count == 0 or section_count > _MAX_SECTIONS:
        raise ParseError(f"지원하지 않는 PE section 수입니다: {section_count}")
    optional_offset = pe_offset + 24
    optional_end = optional_offset + optional_size
    if optional_end > len(data):
        raise ParseError("선택 헤더가 파일 끝을 넘어갑니다.")
    magic = _unpack_from("<H", data, optional_offset)[0]
    if magic == 0x10B:
        bits, pe_type = 32, "PE32"
        required_size = 96
        image_base = _unpack_from("<I", data, optional_offset + 28)[0]
        directory_count_offset = 92
        directory_offset = 96
    elif magic == 0x20B:
        bits, pe_type = 64, "PE32+"
        required_size = 112
        image_base = _unpack_from("<Q", data, optional_offset + 24)[0]
        directory_count_offset = 108
        directory_offset = 112
    else:
        raise ParseError(f"지원하지 않는 PE optional magic입니다: 0x{magic:x}")
    if optional_size < required_size:
        raise ParseError("잘린 PE optional header입니다.")

    entry_rva = _unpack_from("<I", data, optional_offset + 16)[0]
    section_alignment, file_alignment = _unpack_from("<II", data, optional_offset + 32)
    size_of_image, size_of_headers = _unpack_from("<II", data, optional_offset + 56)
    subsystem, dll_characteristics = _unpack_from("<HH", data, optional_offset + 68)
    directory_count = min(
        _unpack_from("<I", data, optional_offset + directory_count_offset)[0], 16
    )
    available_directories = max(0, (optional_size - directory_offset) // 8)
    directory_count = min(directory_count, available_directories)
    directory_names = (
        "export",
        "import",
        "resource",
        "exception",
        "security",
        "base_relocation",
        "debug",
        "architecture",
        "global_pointer",
        "tls",
        "load_config",
        "bound_import",
        "iat",
        "delay_import",
        "clr_runtime",
        "reserved",
    )
    directories: dict[str, tuple[int, int]] = {}
    for index in range(directory_count):
        directories[directory_names[index]] = _unpack_from(
            "<II", data, optional_offset + directory_offset + index * 8
        )

    section_offset = optional_end
    if section_offset + section_count * 40 > len(data):
        raise ParseError("잘린 PE section table입니다.")
    sections: list[PESectionInfo] = []
    for index in range(section_count):
        offset = section_offset + index * 40
        raw_name = data[offset : offset + 8].split(b"\x00", 1)[0]
        name = raw_name.decode("ascii", errors="replace") or f"section_{index}"
        virtual_size, rva, raw_size, raw_offset = _unpack_from(
            "<IIII", data, offset + 8
        )
        section_characteristics = _unpack_from("<I", data, offset + 36)[0]
        if raw_size and (raw_offset > len(data) or raw_size > len(data) - raw_offset):
            raise ParseError(f"{name} section raw range가 파일을 벗어났습니다.")
        blob = data[raw_offset : raw_offset + raw_size] if raw_size else b""
        sections.append(
            PESectionInfo(
                name=name,
                rva=rva,
                addr=image_base + rva,
                virtual_size=virtual_size,
                offset=raw_offset,
                size=raw_size,
                characteristics=section_characteristics,
                readable=bool(section_characteristics & 0x40000000),
                writable=bool(section_characteristics & 0x80000000),
                executable=bool(section_characteristics & 0x20000000),
                entropy=round(shannon_entropy(blob), 4),
            )
        )

    image = PEImage(
        data=data,
        machine=_MACHINE_NAMES.get(
            machine_id, f"IMAGE_FILE_MACHINE_0x{machine_id:04X}"
        ),
        machine_id=machine_id,
        bits=bits,
        pe_type=pe_type,
        file_type="DLL" if characteristics & 0x2000 else "EXE",
        timestamp=timestamp,
        characteristics=characteristics,
        dll_characteristics=dll_characteristics,
        image_base=image_base,
        entry_rva=entry_rva,
        entry=image_base + entry_rva if entry_rva else 0,
        section_alignment=section_alignment,
        file_alignment=file_alignment,
        size_of_image=size_of_image,
        size_of_headers=size_of_headers,
        subsystem=_SUBSYSTEM_NAMES.get(subsystem, f"UNKNOWN_{subsystem}"),
        sections=sections,
        data_directories=directories,
    )
    image.imports = _parse_imports(image)
    image.exports = _parse_exports(image)
    image.relocations = _parse_relocations(image)
    return image


def _parse_imports(image: PEImage) -> list[PEImportInfo]:
    directory_rva, directory_size = image.data_directories.get("import", (0, 0))
    if not directory_rva or not directory_size:
        return []
    directory_offset = _rva_to_offset(image, directory_rva)
    if directory_offset is None:
        raise ParseError(
            "PE import directory RVA를 파일 오프셋으로 변환할 수 없습니다."
        )
    output: list[PEImportInfo] = []
    max_descriptors = min(max(1, directory_size // 20 + 1), 4096)
    for descriptor_index in range(max_descriptors):
        offset = directory_offset + descriptor_index * 20
        descriptor = _unpack_from("<IIIII", image.data, offset)
        original_thunk, timestamp, forwarder, name_rva, first_thunk = descriptor
        if not any((original_thunk, timestamp, forwarder, name_rva, first_thunk)):
            break
        name_offset = _rva_to_offset(image, name_rva)
        if name_offset is None:
            raise ParseError("PE import DLL name RVA가 유효하지 않습니다.")
        library = _read_cstring(image.data, name_offset, max_length=512)
        thunk_rva = original_thunk or first_thunk
        thunk_offset = _rva_to_offset(image, thunk_rva)
        if thunk_offset is None:
            continue
        width = 8 if image.bits == 64 else 4
        ordinal_mask = 1 << (image.bits - 1)
        value_mask = ordinal_mask - 1
        for thunk_index in range(_MAX_IMPORTS - len(output)):
            value = _unpack_from(
                "<Q" if width == 8 else "<I",
                image.data,
                thunk_offset + thunk_index * width,
            )[0]
            if value == 0:
                break
            iat_rva = first_thunk + thunk_index * width
            if value & ordinal_mask:
                ordinal = value & 0xFFFF
                output.append(
                    PEImportInfo(
                        name=f"ordinal_{ordinal}",
                        library=library,
                        address=image.image_base + iat_rva,
                        rva=iat_rva,
                        ordinal=ordinal,
                        hint=None,
                    )
                )
            else:
                hint_name_offset = _rva_to_offset(image, value & value_mask)
                if hint_name_offset is None:
                    break
                hint = _unpack_from("<H", image.data, hint_name_offset)[0]
                name = _read_cstring(image.data, hint_name_offset + 2, max_length=4096)
                output.append(
                    PEImportInfo(
                        name=name,
                        library=library,
                        address=image.image_base + iat_rva,
                        rva=iat_rva,
                        ordinal=None,
                        hint=hint,
                    )
                )
            if len(output) >= _MAX_IMPORTS:
                return output
    return output


def _parse_exports(image: PEImage) -> list[PEExportInfo]:
    directory_rva, directory_size = image.data_directories.get("export", (0, 0))
    if not directory_rva or directory_size < 40:
        return []
    offset = _rva_to_offset(image, directory_rva)
    if offset is None:
        raise ParseError("PE export directory RVA가 유효하지 않습니다.")
    fields = _unpack_from("<IIHHIIIIIII", image.data, offset)
    (
        _,
        _,
        _,
        _,
        _,
        ordinal_base,
        function_count,
        name_count,
        functions_rva,
        names_rva,
        ordinals_rva,
    ) = fields
    if name_count > _MAX_EXPORTS or function_count > _MAX_EXPORTS:
        raise ParseError("PE export table이 분석 한계를 초과했습니다.")
    functions_offset = _rva_to_offset(image, functions_rva)
    names_offset = _rva_to_offset(image, names_rva)
    ordinals_offset = _rva_to_offset(image, ordinals_rva)
    if None in {functions_offset, names_offset, ordinals_offset}:
        raise ParseError("PE export table 배열이 잘못되었습니다.")
    assert functions_offset is not None
    assert names_offset is not None
    assert ordinals_offset is not None
    output: list[PEExportInfo] = []
    for index in range(name_count):
        name_rva = _unpack_from("<I", image.data, names_offset + index * 4)[0]
        ordinal_index = _unpack_from("<H", image.data, ordinals_offset + index * 2)[0]
        if ordinal_index >= function_count:
            continue
        function_rva = _unpack_from(
            "<I", image.data, functions_offset + ordinal_index * 4
        )[0]
        name_offset = _rva_to_offset(image, name_rva)
        if name_offset is None:
            continue
        output.append(
            PEExportInfo(
                name=_read_cstring(image.data, name_offset, max_length=4096),
                address=image.image_base + function_rva,
                rva=function_rva,
                ordinal=ordinal_base + ordinal_index,
            )
        )
    return output


def _parse_relocations(image: PEImage) -> list[PERelocationInfo]:
    directory_rva, directory_size = image.data_directories.get(
        "base_relocation", (0, 0)
    )
    if not directory_rva or directory_size < 8:
        return []
    offset = _rva_to_offset(image, directory_rva)
    if offset is None:
        raise ParseError("PE base relocation directory RVA가 유효하지 않습니다.")
    end = min(len(image.data), offset + directory_size)
    output: list[PERelocationInfo] = []
    cursor = offset
    while cursor + 8 <= end and len(output) < _MAX_RELOCATIONS:
        page_rva, block_size = _unpack_from("<II", image.data, cursor)
        if not page_rva and not block_size:
            break
        if block_size < 8 or block_size > end - cursor:
            raise ParseError("PE base relocation block 크기가 잘못되었습니다.")
        entry_count = (block_size - 8) // 2
        for index in range(entry_count):
            value = _unpack_from("<H", image.data, cursor + 8 + index * 2)[0]
            relocation_type = value >> 12
            relocation_offset = value & 0xFFF
            if relocation_type == 0:
                continue
            rva = page_rva + relocation_offset
            output.append(
                PERelocationInfo(
                    address=image.image_base + rva,
                    rva=rva,
                    page_rva=page_rva,
                    relocation_type=_RELOCATION_NAMES.get(
                        relocation_type, f"TYPE_{relocation_type}"
                    ),
                    relocation_type_id=relocation_type,
                )
            )
            if len(output) >= _MAX_RELOCATIONS:
                break
        cursor += block_size
    return output


def _rva_to_offset(image: PEImage, rva: int) -> int | None:
    if 0 <= rva < image.size_of_headers and rva < len(image.data):
        return rva
    for section in image.sections:
        span = max(section.virtual_size, section.size)
        if section.rva <= rva < section.rva + span:
            delta = rva - section.rva
            if delta >= section.size:
                return None
            offset = section.offset + delta
            return offset if offset < len(image.data) else None
    return None


def _unpack_from(fmt: str, data: bytes, offset: int) -> tuple:
    size = struct.calcsize(fmt)
    if offset < 0 or offset > len(data) - size:
        raise ParseError("잘린 PE: 구조체가 파일 범위를 벗어났습니다.")
    return struct.unpack_from(fmt, data, offset)


def _read_cstring(data: bytes, offset: int, *, max_length: int) -> str:
    if offset < 0 or offset >= len(data):
        raise ParseError("PE 문자열 오프셋이 유효하지 않습니다.")
    end_limit = min(len(data), offset + max_length)
    end = data.find(b"\x00", offset, end_limit)
    if end == -1:
        raise ParseError("PE 문자열이 분석 한계 안에서 종료되지 않았습니다.")
    return data[offset:end].decode("utf-8", errors="replace")
