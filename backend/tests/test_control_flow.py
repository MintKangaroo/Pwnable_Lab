"""Phase 3 function recovery, xref, and CFG tests."""

from __future__ import annotations

import struct

from pwnable_lab.analyzer.control_flow import ControlFlowAnalyzer
from pwnable_lab.elf.parser import parse_elf
from pwnable_lab.pe.parser import parse_pe
from tests.fixtures import sample_control_flow_elf, sample_pe, sample_raw


def test_function_boundaries_cfg_and_xrefs_are_evidence_based():
    image = parse_elf(sample_control_flow_elf())
    analyzer = ControlFlowAnalyzer.from_elf(image)
    functions, truncated = analyzer.functions(max_instructions=200)
    by_name = {item.name: item for item in functions}

    assert truncated is False
    assert by_name["main"].verification == "verified"
    assert by_name["main"].boundary_verification == "verified"
    assert by_name["helper"].address == image.symbol("helper").addr

    cfg = analyzer.cfg(by_name["main"].address, max_instructions=200)
    assert cfg["status"] == "completed"
    assert cfg["node_count"] == 3
    assert {edge["type"] for edge in cfg["edges"]} == {"true", "false"}
    assert any(node["conditional_branch"] for node in cfg["nodes"])
    assert any(
        by_name["helper"].address in node["call_targets"] for node in cfg["nodes"]
    )

    xrefs, xrefs_truncated = analyzer.xrefs(
        address=by_name["helper"].address,
        direction="to",
        kind="call",
        max_instructions=200,
    )
    assert xrefs_truncated is False
    assert len(xrefs) == 1
    assert xrefs[0].source_function == "main"
    assert xrefs[0].target_function == "helper"
    assert xrefs[0].verification == "verified"


def test_control_flow_api_supports_hex_addresses_and_rejects_raw(client):
    uploaded = client.post(
        "/api/v1/binaries",
        files={
            "file": (
                "control-flow.elf",
                sample_control_flow_elf(),
                "application/octet-stream",
            )
        },
    ).json()
    binary_id = uploaded["binary_id"]

    functions = client.get(f"/api/v1/binaries/{binary_id}/functions")
    assert functions.status_code == 200
    main = next(item for item in functions.json()["items"] if item["name"] == "main")
    helper = next(
        item for item in functions.json()["items"] if item["name"] == "helper"
    )

    detail = client.get(f"/api/v1/binaries/{binary_id}/functions/{main['address']:#x}")
    cfg = client.get(f"/api/v1/binaries/{binary_id}/functions/{main['address']:#x}/cfg")
    xrefs = client.get(
        f"/api/v1/binaries/{binary_id}/xrefs",
        params={"address": f"{helper['address']:#x}", "kind": "call"},
    )
    assert detail.status_code == 200
    assert detail.json()["instruction_count"] == 6
    assert cfg.status_code == 200
    assert cfg.json()["node_count"] == 3
    assert xrefs.status_code == 200
    assert xrefs.json()["total"] == 1

    invalid = client.get(f"/api/v1/binaries/{binary_id}/functions/not-an-address")
    assert invalid.status_code == 400

    raw = client.post(
        "/api/v1/binaries",
        files={"file": ("raw.bin", sample_raw(), "application/octet-stream")},
    ).json()
    unavailable = client.get(f"/api/v1/binaries/{raw['binary_id']}/functions")
    assert unavailable.status_code == 400
    assert "unavailable for raw" in unavailable.json()["detail"].lower()


def test_pe_entry_and_rip_relative_import_xref_are_separated():
    data = bytearray(sample_pe())
    # call qword ptr [rip+0x106a] resolves to the verified CreateProcessA IAT slot.
    data[0x200:0x206] = b"\xff\x15" + struct.pack("<i", 0x106A)
    data[0x206] = 0xC3
    image = parse_pe(bytes(data))
    analyzer = ControlFlowAnalyzer.from_pe(image)

    functions, truncated = analyzer.functions(max_instructions=600)
    assert truncated is False
    assert functions[0].name == "entry"
    assert functions[0].address_verification == "verified"
    assert functions[0].boundary_verification == "inferred"

    xrefs, xrefs_truncated = analyzer.xrefs(
        address=image.imports[0].address,
        direction="to",
        kind="call",
        max_instructions=600,
    )
    assert xrefs_truncated is False
    assert len(xrefs) == 1
    assert xrefs[0].target_kind == "memory"
    assert xrefs[0].target_symbol == "KERNEL32.dll!CreateProcessA"
