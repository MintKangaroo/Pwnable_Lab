"""UPX 언패킹 — 패킹된 ELF 를 `upx -d` 로 복원 (Phase 6C 후속).

:func:`analyzer.packing.detect_packing` 이 UPX 로 판별한 바이너리를 실제로 언패킹한다.
``upx -d`` 는 **압축을 풀 뿐 대상을 실행하지 않으므로** 샌드박스 실행 게이트가 필요
없다(그래도 ELF 포맷은 요구한다). ``upx`` 가 PATH 에 없으면 그 사실을 보고하고 넘어
간다(이 호스트는 sudo 불가 — 포터블 upx 를 ``~/.local/bin`` 에 두면 자동 인식된다).
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile

from pwnable_lab.analyzer.packing import detect_packing
from pwnable_lab.elf.parser import parse_elf
from pwnable_lab.formats import ArtifactFormat, detect_format

# upx -d 서브프로세스 벽시계 상한.
_UPX_TIMEOUT_SECONDS = 30.0


def unpack_upx(data: bytes) -> dict:
    """UPX 로 패킹된 ELF 를 언패킹해 메타데이터를 반환한다(대상 미실행).

    반환:
      - 비 ELF/비 UPX: ``{"attempted": False, "reason": ...}``
      - upx 미설치: ``{"attempted": False, "reason": "upx-unavailable"}``
      - 성공: ``{"attempted": True, "unpacked": True, "original_size",
        "unpacked_size", "unpacked_sha256", "packer": "UPX"}``
      - upx 실패: ``{"attempted": True, "unpacked": False, "reason": ...}``
    """

    if detect_format(data) is not ArtifactFormat.ELF:
        return {"attempted": False, "reason": "not-elf"}
    report = detect_packing(parse_elf(data))
    if report.packer != "UPX":
        return {"attempted": False, "reason": "not-upx-packed"}

    upx = shutil.which("upx")
    if upx is None:
        return {"attempted": False, "reason": "upx-unavailable"}

    tmpdir = tempfile.mkdtemp(prefix="plab-upx-")
    packed_path = os.path.join(tmpdir, "packed")
    try:
        with open(packed_path, "wb") as fh:
            fh.write(data)
        # -d 로 제자리(복사본) 복원. 대상을 실행하지 않는다.
        try:
            proc = subprocess.run(
                [upx, "-d", "-q", packed_path],
                capture_output=True,
                timeout=_UPX_TIMEOUT_SECONDS,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return {"attempted": True, "unpacked": False, "reason": "upx-timeout"}
        if proc.returncode != 0:
            detail = proc.stderr.decode("utf-8", "replace").strip()[:200]
            return {
                "attempted": True,
                "unpacked": False,
                "reason": f"upx-failed: {detail or proc.returncode}",
            }
        unpacked = open(packed_path, "rb").read()
        return {
            "attempted": True,
            "unpacked": True,
            "packer": "UPX",
            "original_size": len(data),
            "unpacked_size": len(unpacked),
            "unpacked_sha256": hashlib.sha256(unpacked).hexdigest(),
        }
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


__all__ = ["unpack_upx"]
