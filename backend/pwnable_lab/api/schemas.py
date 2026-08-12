"""API 요청/응답 스키마 (pydantic v2)."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class HealthResponse(BaseModel):
    status: str
    version: str


class BinarySummary(BaseModel):
    sha256: str
    filename: str
    size: int
    format: str
    machine: str
    bits: int
    analysis_status: str
    created_at: datetime


class BinaryDetail(BinarySummary):
    updated_at: datetime


class UploadResponse(BaseModel):
    binary_id: str
    sha256: str
    filename: str
    size: int
    format: str
    analysis_status: str


class AnalysisJobResponse(BaseModel):
    job_id: str
    binary_id: str
    status: Literal["queued", "running", "completed", "failed"]
    analyzer_name: str
    analyzer_version: str
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None
    confidence: float
    evidence: list
    result: dict | None
    error: str | None


class CrashSummary(BaseModel):
    crash_id: str
    sha256: str
    filename: str
    size: int
    artifact_kind: Literal["text_log", "core_dump"]
    binary_id: str | None
    analysis_status: str
    signal: str | None
    created_at: datetime


class CrashDetail(CrashSummary):
    analyzer_name: str
    analyzer_version: str
    confidence: float
    evidence: list
    result: dict


# --- 페이로드 도구 ---
class CyclicRequest(BaseModel):
    length: int = Field(gt=0, le=65_536)
    n: int = Field(default=4, ge=2, le=8)


class CyclicResponse(BaseModel):
    length: int
    pattern_hex: str
    pattern_ascii: str


class CyclicFindRequest(BaseModel):
    value: str = Field(description="4바이트 부분 문자열 또는 0x 접두 정수")
    n: int = Field(default=4, ge=2, le=8)


class CyclicFindResponse(BaseModel):
    offset: int


class PackRequest(BaseModel):
    value: int
    bits: Literal[32, 64] = 64
    endian: Literal["little", "big"] = "little"


class PackResponse(BaseModel):
    hex: str
    bytes: list[int]


class OverflowRequest(BaseModel):
    padding: int = Field(ge=0, le=1_000_000)
    target: int
    bits: Literal[32, 64] = 64
    fill: str = Field(default="A", min_length=1, max_length=32)
    chain: list[int] = Field(default_factory=list)


class OverflowResponse(BaseModel):
    length: int
    payload_hex: str
    hexdump: str


class RopChainItem(BaseModel):
    kind: Literal["gadget", "literal", "symbol", "padding"]
    value: int = Field(ge=0, le=0xFFFFFFFFFFFFFFFF)
    label: str = Field(default="", max_length=128)

    @field_validator("value", mode="before")
    @classmethod
    def parse_integer(cls, value: object) -> object:
        if isinstance(value, str):
            try:
                return int(value, 0)
            except ValueError as exc:
                raise ValueError(
                    "value must be a decimal or 0x-prefixed integer"
                ) from exc
        return value


class RopSimulationRequest(BaseModel):
    items: list[RopChainItem] = Field(default_factory=list, max_length=256)
    initial_rsp_mod16: int = Field(default=0, ge=0, le=15)


# --- 문제 ---
class SubmitRequest(BaseModel):
    answer: str


class SubmitResponse(BaseModel):
    correct: bool
    solution: str | None = None
    message: str
