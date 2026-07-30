"""페이로드 제작 도구 라우트 — cyclic, pack, overflow, shellcode."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from pwnable_lab.api.dependencies import get_config
from pwnable_lab.api.schemas import (
    CyclicFindRequest,
    CyclicFindResponse,
    CyclicRequest,
    CyclicResponse,
    OverflowRequest,
    OverflowResponse,
    PackRequest,
    PackResponse,
)
from pwnable_lab.config import Settings
from pwnable_lab.errors import AnalysisError
from pwnable_lab.payload.cyclic import cyclic, cyclic_find
from pwnable_lab.payload.pack import (
    RopStep,
    build_overflow,
    hexdump_payload,
    p32,
    p64,
)
from pwnable_lab.payload.shellcode import get_shellcode, list_shellcode

router = APIRouter(prefix="/payload", tags=["payload"])


@router.post("/cyclic", response_model=CyclicResponse)
def make_cyclic(
    req: CyclicRequest, settings: Settings = Depends(get_config)
) -> CyclicResponse:
    if req.length > settings.max_cyclic_length:
        raise AnalysisError(
            f"length 가 한계({settings.max_cyclic_length})를 초과했습니다."
        )
    pattern = cyclic(req.length, n=req.n)
    ascii_ = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in pattern)
    return CyclicResponse(
        length=req.length, pattern_hex=pattern.hex(), pattern_ascii=ascii_
    )


@router.post("/cyclic/find", response_model=CyclicFindResponse)
def find_cyclic(req: CyclicFindRequest) -> CyclicFindResponse:
    raw = req.value.strip()
    try:
        if raw.lower().startswith("0x"):
            offset = cyclic_find(int(raw, 16), n=req.n, max_length=65_536)
        else:
            offset = cyclic_find(raw.encode(), n=req.n, max_length=65_536)
    except (ValueError, OverflowError) as exc:
        raise AnalysisError(str(exc)) from exc
    return CyclicFindResponse(offset=offset)


@router.post("/pack", response_model=PackResponse)
def pack(req: PackRequest) -> PackResponse:
    packer = p64 if req.bits == 64 else p32
    raw = packer(req.value, req.endian)
    return PackResponse(hex=raw.hex(), bytes=list(raw))


@router.post("/overflow", response_model=OverflowResponse)
def overflow(req: OverflowRequest) -> OverflowResponse:
    payload = build_overflow(
        req.padding,
        req.target,
        bits=req.bits,
        fill=req.fill.encode() or b"A",
        chain=[RopStep(v) for v in req.chain],
    )
    return OverflowResponse(
        length=len(payload),
        payload_hex=payload.hex(),
        hexdump=hexdump_payload(payload),
    )


@router.get("/shellcode")
def shellcode(arch: str | None = Query(default=None)) -> list[dict]:
    return [s.as_dict() for s in list_shellcode(arch)]


@router.get("/shellcode/{slug}")
def shellcode_one(slug: str) -> dict:
    sc = get_shellcode(slug)
    if sc is None:
        from pwnable_lab.errors import NotFoundError

        raise NotFoundError(f"셸코드를 찾을 수 없습니다: {slug}")
    return sc.as_dict()
