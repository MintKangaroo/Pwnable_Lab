"""Phase 3 gadget semantics, filtering, and inferred chain simulation tests."""

from __future__ import annotations

import pytest

from pwnable_lab.analyzer.gadgets import (
    GadgetFilter,
    filter_gadgets,
    find_gadgets,
    scan_gadgets,
    search_gadgets,
    simulate_chain,
)
from pwnable_lab.elf.parser import ElfImage, SectionInfo, parse_elf
from pwnable_lab.errors import AnalysisError
from tests.fixtures import sample_gadget_elf


def _gadget(gadgets, text: str):  # noqa: ANN001, ANN202
    return next(item for item in gadgets if item.text == text)


def test_gadget_effects_and_categories_are_evidence_based():
    image = parse_elf(sample_gadget_elf())
    gadgets = find_gadgets(image, max_gadgets=500, max_depth=5)

    pop_rdi = _gadget(gadgets, "pop rdi ; ret")
    assert pop_rdi.stack_change == 16
    assert pop_rdi.stack_words == 2
    assert pop_rdi.popped_registers == ["rdi"]
    assert "rdi" in pop_rdi.registers_written
    assert pop_rdi.memory_read is True
    assert pop_rdi.memory_write is False
    assert pop_rdi.quality_score >= 0.9
    assert pop_rdi.verification == "verified"

    leave_ret = _gadget(gadgets, "leave ; ret")
    assert leave_ret.stack_change is None
    assert "stack_pivot" in leave_ret.categories

    write = _gadget(gadgets, "mov qword ptr [rdi], rax ; ret")
    assert write.memory_write is True
    assert "write_what_where_candidate" in write.categories
    assert write.quality_score < pop_rdi.quality_score

    assert "syscall" in _gadget(gadgets, "syscall").categories
    assert "int80" in _gadget(gadgets, "int 0x80").categories
    assert _gadget(gadgets, "ret 0x10").stack_change == 24


def test_gadget_filters_cover_register_regex_stack_and_bad_bytes():
    image = parse_elf(sample_gadget_elf())
    gadgets = find_gadgets(image, max_gadgets=500, max_depth=5)
    pop_rdi = _gadget(gadgets, "pop rdi ; ret")

    filtered = filter_gadgets(
        gadgets,
        GadgetFilter(
            query=r"^pop r[dsi]i? ; ret$",
            regex=True,
            register="rdi",
            min_stack_change=16,
            max_stack_change=16,
        ),
        bits=image.bits,
        endian=image.endian,
    )
    assert pop_rdi in filtered

    address_bytes = pop_rdi.address.to_bytes(8, "little")
    excluded = filter_gadgets(
        gadgets,
        GadgetFilter(bad_bytes=(address_bytes[0],)),
        bits=image.bits,
        endian=image.endian,
    )
    assert pop_rdi not in excluded

    bounded = filter_gadgets(
        gadgets,
        GadgetFilter(
            category="return",
            max_stack_change=8,
            address_min=pop_rdi.address,
            address_max=pop_rdi.address + 0x100,
            sort="address",
            order="asc",
        ),
        bits=image.bits,
        endian=image.endian,
    )
    assert bounded == sorted(bounded, key=lambda item: item.address)
    assert all(
        item.stack_change is not None and item.stack_change <= 8 for item in bounded
    )
    assert all(
        pop_rdi.address <= item.address <= pop_rdi.address + 0x100 for item in bounded
    )

    side_effects = filter_gadgets(
        gadgets,
        GadgetFilter(sort="side_effects", order="asc"),
        bits=image.bits,
        endian=image.endian,
    )
    assert side_effects[0].side_effect_count <= side_effects[-1].side_effect_count
    stack_sorted = filter_gadgets(
        gadgets,
        GadgetFilter(sort="stack_change", order="desc"),
        bits=image.bits,
        endian=image.endian,
    )
    assert stack_sorted
    assert search_gadgets(gadgets, "") == gadgets

    with pytest.raises(AnalysisError, match="Unsupported gadget sort"):
        filter_gadgets(
            gadgets,
            GadgetFilter(sort="unknown"),
            bits=image.bits,
            endian=image.endian,
        )
    with pytest.raises(AnalysisError, match="repetition"):
        filter_gadgets(
            gadgets,
            GadgetFilter(query="a*a*a*a*a*", regex=True),
            bits=image.bits,
            endian=image.endian,
        )
    with pytest.raises(AnalysisError, match="Invalid gadget regex"):
        filter_gadgets(
            gadgets,
            GadgetFilter(query="[", regex=True),
            bits=image.bits,
            endian=image.endian,
        )


def test_scan_reports_pie_offsets_truncation_and_unsupported_architecture():
    pie_image = parse_elf(sample_gadget_elf(pie=True))
    scan = scan_gadgets(pie_image, max_gadgets=2, max_depth=5)
    assert scan.truncated is True
    assert scan.position_independent is True
    assert len(scan.gadgets) == 2
    assert all(
        item.pie_offset == item.address - scan.image_base for item in scan.gadgets
    )

    pie_image.machine = "EM_AARCH64"
    with pytest.raises(AnalysisError, match="x86/x86-64"):
        find_gadgets(pie_image)


def test_x86_32_gadget_uses_four_byte_stack_words():
    code = b"\x58\xc3"  # pop eax ; ret
    image = ElfImage(
        data=code,
        bits=32,
        endian="little",
        machine="EM_386",
        e_type="ET_EXEC",
        entry=0x8048000,
        sections=[
            SectionInfo(
                name=".text",
                addr=0x8048000,
                offset=0,
                size=len(code),
                flags=0x6,
                stype="SHT_PROGBITS",
                executable=True,
                writable=False,
            )
        ],
    )
    gadget = _gadget(find_gadgets(image), "pop eax ; ret")
    assert gadget.stack_change == 8
    assert gadget.stack_words == 2


def test_chain_simulation_tracks_stack_registers_and_terminal_target():
    image = parse_elf(sample_gadget_elf())
    gadgets = find_gadgets(image, max_gadgets=500, max_depth=5)
    pop_rdi = _gadget(gadgets, "pop rdi ; ret")
    ret = _gadget(gadgets, "ret")
    report = simulate_chain(
        gadgets,
        [
            {"kind": "gadget", "value": pop_rdi.address, "label": pop_rdi.text},
            {"kind": "literal", "value": 0xDEADBEEF, "label": "argument"},
            {"kind": "gadget", "value": ret.address, "label": ret.text},
            {"kind": "symbol", "value": 0x401234, "label": "target"},
        ],
        bits=64,
        position_independent=False,
        initial_rsp_mod16=0,
    )
    assert report["status"] == "valid"
    assert report["verification"] == "inferred"
    assert report["success_verified"] is False
    assert report["registers"]["rdi"]["value"] == 0xDEADBEEF
    assert report["final_target"]["value"] == 0x401234
    assert report["rsp_delta"] == 24
    assert report["final_rsp_mod16"] == 8
    assert len(report["trace"]) == 2


def test_chain_simulation_reports_unsupported_and_incomplete_layouts():
    image = parse_elf(sample_gadget_elf())
    gadgets = find_gadgets(image, max_gadgets=500, max_depth=5)
    pop_rdi = _gadget(gadgets, "pop rdi ; ret")
    ret = _gadget(gadgets, "ret")

    empty = simulate_chain(
        gadgets,
        [],
        bits=64,
        position_independent=False,
        initial_rsp_mod16=0,
    )
    assert empty["status"] == "invalid"
    first_literal = simulate_chain(
        gadgets,
        [{"kind": "literal", "value": 1, "label": ""}],
        bits=64,
        position_independent=False,
        initial_rsp_mod16=0,
    )
    assert first_literal["status"] == "invalid"
    unknown = simulate_chain(
        gadgets,
        [{"kind": "gadget", "value": 1, "label": ""}],
        bits=64,
        position_independent=False,
        initial_rsp_mod16=0,
    )
    assert unknown["status"] == "invalid"
    missing_pop_value = simulate_chain(
        gadgets,
        [{"kind": "gadget", "value": pop_rdi.address, "label": ""}],
        bits=64,
        position_independent=False,
        initial_rsp_mod16=0,
    )
    assert missing_pop_value["status"] == "invalid"
    return_beyond = simulate_chain(
        gadgets,
        [{"kind": "gadget", "value": ret.address, "label": ""}],
        bits=64,
        position_independent=True,
        initial_rsp_mod16=8,
    )
    assert return_beyond["status"] == "warning"
    assert any("PIE is enabled" in item for item in return_beyond["warnings"])


@pytest.mark.parametrize(
    ("text", "expected_status", "message"),
    [
        ("push rax ; ret", "invalid", "Backward stack write"),
        ("call rax ; ret", "warning", "unmodelled code"),
        ("leave ; ret", "warning", "frame pointer"),
        ("mov rsp, rax ; ret", "warning", "data-dependent"),
        ("xchg rsp, rax ; ret", "warning", "data-dependent"),
        ("sub rsp, 0x10 ; ret", "invalid", "Backward stack adjustment"),
    ],
)
def test_chain_simulation_stops_on_data_dependent_stack_effects(
    text: str, expected_status: str, message: str
):
    image = parse_elf(sample_gadget_elf())
    gadgets = find_gadgets(image, max_gadgets=500, max_depth=5)
    gadget = _gadget(gadgets, text)
    report = simulate_chain(
        gadgets,
        [
            {"kind": "gadget", "value": gadget.address, "label": text},
            {"kind": "literal", "value": 0x41414141, "label": "next"},
        ],
        bits=64,
        position_independent=False,
        initial_rsp_mod16=0,
    )
    assert report["status"] == expected_status
    assert any(message in item for item in report["errors"] + report["warnings"])


def test_chain_simulation_handles_stack_skip_syscall_and_memory_warning():
    image = parse_elf(sample_gadget_elf())
    gadgets = find_gadgets(image, max_gadgets=500, max_depth=5)
    add_rsp = _gadget(gadgets, "add rsp, 0x10 ; ret")
    syscall = _gadget(gadgets, "syscall")
    memory_write = _gadget(gadgets, "mov qword ptr [rdi], rax ; ret")

    skipped = simulate_chain(
        gadgets,
        [
            {"kind": "gadget", "value": add_rsp.address, "label": "adjust"},
            {"kind": "padding", "value": 0, "label": "skip"},
            {"kind": "padding", "value": 0, "label": "skip"},
            {"kind": "symbol", "value": 0x401234, "label": "target"},
        ],
        bits=64,
        position_independent=False,
        initial_rsp_mod16=0,
    )
    assert skipped["status"] == "valid"
    assert skipped["final_target"]["value"] == 0x401234

    skip_beyond = simulate_chain(
        gadgets,
        [{"kind": "gadget", "value": add_rsp.address, "label": "adjust"}],
        bits=64,
        position_independent=False,
        initial_rsp_mod16=0,
    )
    assert skip_beyond["status"] == "invalid"

    effect = simulate_chain(
        gadgets,
        [
            {"kind": "gadget", "value": syscall.address, "label": "syscall"},
            {"kind": "literal", "value": 1, "label": "unused"},
        ],
        bits=64,
        position_independent=False,
        initial_rsp_mod16=0,
    )
    assert effect["final_target"]["label"] == "syscall"
    assert any("not consumed" in item for item in effect["warnings"])

    write = simulate_chain(
        gadgets,
        [
            {"kind": "gadget", "value": memory_write.address, "label": "write"},
            {"kind": "symbol", "value": 0x401234, "label": "target"},
        ],
        bits=64,
        position_independent=False,
        initial_rsp_mod16=0,
    )
    assert write["status"] == "warning"
    assert any("writes memory" in item for item in write["warnings"])


def test_rop_api_paginates_filters_and_simulates(client):
    uploaded = client.post(
        "/api/v1/binaries",
        files={
            "file": ("gadgets.elf", sample_gadget_elf(), "application/octet-stream")
        },
    ).json()
    binary_id = uploaded["binary_id"]

    response = client.get(
        f"/api/v1/binaries/{binary_id}/gadgets",
        params={"register": "rdi", "sort": "quality", "limit": 10},
    )
    assert response.status_code == 200
    report = response.json()
    assert report["format"] == "ELF"
    assert report["total"] >= 1
    assert report["verification"] == "verified"
    assert all("rdi" in item["registers_written"] for item in report["items"])

    pop_rdi = next(item for item in report["items"] if item["text"] == "pop rdi ; ret")
    all_gadgets = client.get(f"/api/v1/binaries/{binary_id}/gadgets").json()
    ret = next(item for item in all_gadgets["items"] if item["text"] == "ret")
    simulated = client.post(
        f"/api/v1/binaries/{binary_id}/rop/simulate",
        json={
            "items": [
                {"kind": "gadget", "value": hex(pop_rdi["address"])},
                {"kind": "literal", "value": "0xdeadbeef", "label": "arg"},
                {"kind": "gadget", "value": ret["address"]},
                {"kind": "symbol", "value": "0x401234", "label": "target"},
            ]
        },
    )
    assert simulated.status_code == 200
    assert simulated.json()["status"] == "valid"
    assert simulated.json()["registers"]["rdi"]["value_hex"] == "0xdeadbeef"

    invalid_regex = client.get(
        f"/api/v1/binaries/{binary_id}/gadgets",
        params={"q": "(a+)+", "regex": "true"},
    )
    assert invalid_regex.status_code == 400

    invalid_range = client.get(
        f"/api/v1/binaries/{binary_id}/gadgets",
        params={"min_stack_change": 16, "max_stack_change": 8},
    )
    assert invalid_range.status_code == 400
