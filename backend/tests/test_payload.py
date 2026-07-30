"""페이로드 코어와 API 계약 테스트."""

from __future__ import annotations

import pytest

from pwnable_lab.payload.cyclic import cyclic, cyclic_find
from pwnable_lab.payload.pack import (
    RopStep,
    build_overflow,
    hexdump_payload,
    p32,
    p64,
    u32,
    u64,
)
from pwnable_lab.payload.shellcode import get_shellcode, list_shellcode


def test_cyclic_is_deterministic_and_unique():
    pattern = cyclic(512)
    assert pattern == cyclic(512)
    windows = {pattern[i : i + 4] for i in range(len(pattern) - 3)}
    assert len(windows) == len(pattern) - 3


def test_cyclic_find_bytes_and_register_integer():
    pattern = cyclic(100)
    needle = pattern[44:48]
    assert cyclic_find(needle) == 44
    assert cyclic_find(int.from_bytes(needle, "little")) == 44


def test_cyclic_find_respects_search_limit():
    pattern = cyclic(200)
    assert cyclic_find(pattern[100:104], max_length=50) == -1


def test_cyclic_rejects_invalid_lengths():
    with pytest.raises(ValueError):
        cyclic(-1)
    with pytest.raises(ValueError):
        cyclic(26**4 + 1)
    with pytest.raises(ValueError):
        cyclic_find(b"abc")


@pytest.mark.parametrize("value", [0, 1, 0x401156, 0xFFFFFFFFFFFFFFFF])
def test_pack_roundtrip_64(value):
    assert u64(p64(value)) == value


@pytest.mark.parametrize("endian", ["little", "big"])
def test_pack_roundtrip_32_endian(endian):
    value = 0xDEADBEEF
    assert u32(p32(value, endian), endian) == value


def test_build_overflow_layout_and_hexdump():
    payload = build_overflow(
        8, 0x401000, bits=64, fill=b"AB", chain=[RopStep(0xDEADBEEF)]
    )
    assert payload[:8] == b"ABABABAB"
    assert payload[8:16] == p64(0x401000)
    assert payload[16:24] == p64(0xDEADBEEF)
    assert "00000000" in hexdump_payload(payload)


def test_shellcode_catalog_is_consistent():
    items = list_shellcode()
    assert {item.arch for item in items} == {"amd64", "i386"}
    assert all(item.length == len(bytes.fromhex(item.bytes_hex)) for item in items)
    assert get_shellcode("amd64-execve-sh") in items
    assert get_shellcode("missing") is None


def test_payload_api_cyclic_and_find(client):
    made = client.post("/api/payload/cyclic", json={"length": 100, "n": 4})
    assert made.status_code == 200
    body = made.json()
    needle = body["pattern_ascii"][32:36]
    found = client.post("/api/payload/cyclic/find", json={"value": needle, "n": 4})
    assert found.status_code == 200
    assert found.json()["offset"] == 32


def test_payload_api_pack_and_overflow(client):
    packed = client.post(
        "/api/payload/pack",
        json={"value": 0x401156, "bits": 64, "endian": "little"},
    )
    assert packed.status_code == 200
    assert packed.json()["hex"] == p64(0x401156).hex()

    overflow = client.post(
        "/api/payload/overflow",
        json={
            "padding": 16,
            "target": 0x401156,
            "bits": 64,
            "fill": "A",
            "chain": [0x40101A],
        },
    )
    assert overflow.status_code == 200
    assert overflow.json()["length"] == 32


def test_payload_api_validates_inputs(client):
    assert (
        client.post(
            "/api/payload/pack", json={"value": 1, "bits": 16, "endian": "little"}
        ).status_code
        == 422
    )
    assert (
        client.post("/api/payload/cyclic", json={"length": 65537, "n": 4}).status_code
        == 422
    )
    bad_find = client.post("/api/payload/cyclic/find", json={"value": "x", "n": 4})
    assert bad_find.status_code == 400


def test_shellcode_api(client):
    all_items = client.get("/api/payload/shellcode")
    assert all_items.status_code == 200
    assert len(all_items.json()) >= 3
    amd64 = client.get("/api/payload/shellcode?arch=amd64").json()
    assert all(item["arch"] == "amd64" for item in amd64)
    assert client.get("/api/payload/shellcode/nope").status_code == 404
