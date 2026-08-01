"""PE/EXE and raw-binary static analysis contracts."""

from __future__ import annotations

import pytest

from pwnable_lab.analyzer.entropy import shannon_entropy
from pwnable_lab.errors import AnalysisError, ParseError, UnsupportedFormatError
from pwnable_lab.formats import ArtifactFormat, detect_format
from pwnable_lab.pe.analyzer import disassemble_raw, pe_checksec, scan_pe_imports
from pwnable_lab.pe.parser import parse_pe
from tests.fixtures import sample_pe, sample_raw


def _upload(client, data: bytes, filename: str):  # noqa: ANN001
    return client.post(
        "/api/v1/binaries",
        files={"file": (filename, data, "application/octet-stream")},
    )


def test_format_detection_rejects_archives_and_plain_text():
    assert detect_format(sample_pe()) is ArtifactFormat.PE
    assert detect_format(sample_raw()) is ArtifactFormat.RAW
    with pytest.raises(UnsupportedFormatError):
        detect_format(b"PK\x03\x04" + b"A" * 128)
    with pytest.raises(UnsupportedFormatError):
        detect_format(b"This is a plain text document.\n")
    with pytest.raises(UnsupportedFormatError, match="PNG"):
        detect_format(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)


def test_pe_parser_import_relocation_and_protections():
    image = parse_pe(sample_pe())
    assert image.machine == "IMAGE_FILE_MACHINE_AMD64"
    assert image.bits == 64
    assert image.file_type == "EXE"
    assert image.entry == 0x140001000
    assert image.subsystem == "WINDOWS_CUI"
    assert image.needed_libraries == ["KERNEL32.dll"]
    assert image.imports[0].name == "CreateProcessA"
    assert image.imports[0].address == 0x140002070
    assert image.relocations[0].relocation_type == "DIR64"
    assert image.sections[0].executable is True

    security = pe_checksec(image)
    protections = {item["name"]: item for item in security["protections"]}
    assert protections["aslr"]["enabled"] is True
    assert protections["dep"]["enabled"] is True
    assert protections["control_flow_guard"]["state"] == "declared"
    assert protections["authenticode"]["state"] == "not_detected"

    findings = scan_pe_imports(image)
    assert findings[0]["symbol"] == "CreateProcessA"
    assert findings[0]["status"] == "possible"
    assert findings[0]["verification"] == "inferred"


def test_pe_parser_rejects_truncated_or_invalid_headers():
    with pytest.raises(ParseError):
        parse_pe(b"MZ" + b"\x00" * 10)
    malformed = bytearray(0x80)
    malformed[:2] = b"MZ"
    malformed[0x3C:0x40] = (0x40).to_bytes(4, "little")
    with pytest.raises(ParseError, match="signature"):
        parse_pe(bytes(malformed))


def test_raw_disassembly_requires_explicit_architecture():
    with pytest.raises(AnalysisError, match="explicit architecture"):
        disassemble_raw(
            sample_raw(),
            architecture=None,
            base_address=0x400000,
            address=None,
            count=8,
            max_instructions=100,
        )
    instructions = disassemble_raw(
        sample_raw(),
        architecture="x86_64",
        base_address=0x400000,
        address=None,
        count=4,
        max_instructions=100,
    )
    assert instructions[0].address == 0x400000
    assert instructions[0].mnemonic == "nop"
    assert 0.0 <= shannon_entropy(sample_raw()) <= 8.0


def test_pe_api_upload_analysis_and_capabilities(client):
    uploaded = _upload(client, sample_pe(), "authorized.exe")
    assert uploaded.status_code == 200
    body = uploaded.json()
    assert body["format"] == "PE"
    binary_id = body["binary_id"]

    detail = client.get(f"/api/v1/binaries/{binary_id}")
    info = client.get(f"/api/v1/binaries/{binary_id}/info")
    pe = client.get(f"/api/v1/binaries/{binary_id}/pe")
    assert detail.json()["format"] == "PE"
    assert info.json()["format"] == "PE"
    assert pe.json()["imports"][0]["name"] == "CreateProcessA"
    assert client.get(f"/api/v1/binaries/{binary_id}/elf").status_code == 400

    security = client.get(f"/api/v1/binaries/{binary_id}/checksec")
    imports = client.get(f"/api/v1/binaries/{binary_id}/imports")
    relocations = client.get(f"/api/v1/binaries/{binary_id}/relocations")
    findings = client.get(f"/api/v1/binaries/{binary_id}/vulns")
    disassembly = client.get(
        f"/api/v1/binaries/{binary_id}/disassembly", params={"count": 3}
    )
    entropy = client.get(f"/api/v1/binaries/{binary_id}/entropy")
    assert security.json()["format"] == "PE"
    assert imports.json()["items"][0]["binding"] == "KERNEL32.dll"
    assert relocations.json()["total"] == 1
    assert findings.json()[0]["status"] == "possible"
    assert disassembly.json()[0]["mnemonic"] == "nop"
    assert entropy.json()["format"] == "PE"
    assert len(entropy.json()["regions"]) == 2
    assert client.get(f"/api/v1/binaries/{binary_id}/got").status_code == 400

    analysis = client.post(f"/api/v1/binaries/{binary_id}/analyze")
    result = analysis.json()
    assert result["status"] == "completed"
    assert result["analyzer_name"] == "static_binary"
    assert result["analyzer_version"] == "3.0.0"
    assert result["result"]["format"] == "PE"
    assert result["result"]["pe"]["import_count"] == 1


def test_raw_api_preserves_unknowns_and_allows_opt_in_disassembly(client):
    uploaded = _upload(client, sample_raw(), "shellcode.bin")
    assert uploaded.status_code == 200
    body = uploaded.json()
    assert body["format"] == "RAW"
    binary_id = body["binary_id"]

    info = client.get(f"/api/v1/binaries/{binary_id}/info").json()
    security = client.get(f"/api/v1/binaries/{binary_id}/checksec").json()
    assert info["machine"] == "UNKNOWN"
    assert info["bits"] == 0
    assert info["entry"] is None
    assert security["protections"][0]["verification"] == "unknown"

    missing_arch = client.get(f"/api/v1/binaries/{binary_id}/disassembly")
    disassembly = client.get(
        f"/api/v1/binaries/{binary_id}/disassembly",
        params={
            "architecture": "x86_64",
            "base_address": 0x400000,
            "count": 4,
        },
    )
    strings = client.get(f"/api/v1/binaries/{binary_id}/strings").json()
    entropy = client.get(f"/api/v1/binaries/{binary_id}/entropy").json()
    assert missing_arch.status_code == 400
    assert disassembly.status_code == 200
    assert disassembly.json()[0]["address"] == 0x400000
    oversized_base = client.get(
        f"/api/v1/binaries/{binary_id}/disassembly",
        params={"architecture": "x86_64", "base_address": 1 << 64},
    )
    assert oversized_base.status_code == 422
    assert any(item["value"] == "HELLO" for item in strings)
    assert entropy["format"] == "RAW"
    assert entropy["regions"]

    analysis = client.post(f"/api/v1/binaries/{binary_id}/analyze").json()
    assert analysis["status"] == "completed"
    assert analysis["result"]["verification"] == "unknown"
    assert analysis["result"]["raw"]["entry"] is None


def test_upload_rejects_malformed_pe_and_archives(client):
    malformed = _upload(client, b"MZ" + b"\x00" * 62, "broken.exe")
    archive = _upload(client, b"PK\x03\x04" + b"\x00" * 64, "packed.zip")
    assert malformed.status_code == 422
    assert malformed.json()["error"] == "ParseError"
    assert archive.status_code == 415
    assert archive.json()["error"] == "UnsupportedFormatError"
