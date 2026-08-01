"""Bounded file-format detection without trusting names or MIME values."""

from __future__ import annotations

from enum import Enum

from pwnable_lab.errors import UnsupportedFormatError


class ArtifactFormat(Enum):
    ELF = "ELF"
    PE = "PE"
    RAW = "RAW"


_ARCHIVE_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"PK\x03\x04", "ZIP"),
    (b"PK\x05\x06", "ZIP"),
    (b"PK\x07\x08", "ZIP"),
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "XZ"),
    (b"7z\xbc\xaf'\x1c", "7-Zip"),
    (b"Rar!\x1a\x07", "RAR"),
    (b"(\xb5/\xfd", "Zstandard"),
)
_RECOGNIZED_UNSUPPORTED_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF image"),
    (b"GIF89a", "GIF image"),
    (b"%PDF-", "PDF document"),
    (b"SQLite format 3\x00", "SQLite database"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE compound document"),
    (b"\x00asm", "WebAssembly module"),
    (b"\xcf\xfa\xed\xfe", "Mach-O executable"),
    (b"\xfe\xed\xfa\xcf", "Mach-O executable"),
    (b"\xce\xfa\xed\xfe", "Mach-O executable"),
    (b"\xfe\xed\xfa\xce", "Mach-O executable"),
    (b"\xca\xfe\xba\xbe", "Mach-O/Java container"),
)


def detect_format(data: bytes) -> ArtifactFormat:
    """Classify an ELF, PE, or plausible raw binary.

    Archive/container signatures remain rejected so accepting raw machine code does not
    turn artifact storage into a generic upload service.
    """

    if not data:
        raise UnsupportedFormatError("빈 파일은 분석할 수 없습니다.")
    if data.startswith(b"\x7fELF"):
        return ArtifactFormat.ELF
    if data.startswith(b"MZ"):
        return ArtifactFormat.PE
    for signature, name in _ARCHIVE_SIGNATURES:
        if data.startswith(signature):
            raise UnsupportedFormatError(
                f"{name} 압축/컨테이너 파일은 기본 정책상 거부됩니다."
            )
    for signature, name in _RECOGNIZED_UNSUPPORTED_SIGNATURES:
        if data.startswith(signature):
            raise UnsupportedFormatError(f"{name}은 현재 분석 포맷이 아닙니다.")
    if len(data) > 265 and data[257:262] == b"ustar":
        raise UnsupportedFormatError("TAR 아카이브는 기본 정책상 거부됩니다.")
    if _looks_like_raw_binary(data):
        return ArtifactFormat.RAW
    raise UnsupportedFormatError(
        "ELF, Windows PE/EXE, 또는 기계어 형태의 raw binary만 지원합니다."
    )


def _looks_like_raw_binary(data: bytes) -> bool:
    sample = data[:8192]
    if b"\x00" in sample:
        return True
    text_bytes = sum(byte in {9, 10, 13} or 0x20 <= byte < 0x7F for byte in sample)
    return 1.0 - (text_bytes / len(sample)) >= 0.15
