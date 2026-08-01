"""Phase 2 static ELF analysis against compiler-produced fixtures.

The fixtures are compiled but never executed. Tests skip cleanly when a C compiler is absent.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from pwnable_lab.analyzer.checksec import run_checksec
from pwnable_lab.analyzer.got_plt import analyze_got_plt
from pwnable_lab.analyzer.vuln_scan import scan_vulns
from pwnable_lab.elf.parser import parse_elf

_DYNAMIC_SOURCE = r"""
#include <stdio.h>
#include <string.h>

volatile size_t observed_length;

__attribute__((noinline)) int inspect_argument(const char *value) {
    char buffer[32];
    strcpy(buffer, value);
    observed_length = strlen(buffer);
    puts(buffer);
    return (int)observed_length;
}

int main(int argc, char **argv) {
    return argc > 1 ? inspect_argument(argv[1]) : 0;
}
"""


def _compile(source: str, output: Path, *flags: str) -> bytes:
    compiler = shutil.which("gcc")
    if compiler is None:
        pytest.skip("gcc is required for compiler-produced ELF fixtures")
    source_path = output.with_suffix(".c")
    source_path.write_text(source, encoding="utf-8")
    completed = subprocess.run(
        [compiler, str(source_path), "-o", str(output), *flags],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if completed.returncode != 0:
        pytest.skip(f"fixture compiler flags are unavailable: {completed.stderr}")
    return output.read_bytes()


@pytest.fixture(scope="module")
def dynamic_fixture(tmp_path_factory: pytest.TempPathFactory) -> bytes:
    output = tmp_path_factory.mktemp("phase2-dynamic") / "protected"
    return _compile(
        _DYNAMIC_SOURCE,
        output,
        "-O2",
        "-fPIE",
        "-pie",
        "-rdynamic",
        "-fstack-protector-all",
        "-D_FORTIFY_SOURCE=2",
        "-fcf-protection=full",
        "-Wl,-z,relro,-z,now",
        "-Wl,--enable-new-dtags,-rpath,/opt/pwnpilot-test",
        "-Wl,--build-id",
    )


@pytest.fixture(scope="module")
def static_fixture(tmp_path_factory: pytest.TempPathFactory) -> bytes:
    output = tmp_path_factory.mktemp("phase2-static") / "static"
    return _compile(
        "int main(void) { return 0; }",
        output,
        "-O0",
        "-static",
        "-no-pie",
        "-Wl,--build-id",
    )


def test_dynamic_metadata_and_symbol_classification(dynamic_fixture: bytes):
    image = parse_elf(dynamic_fixture)

    assert image.interpreter and "ld-linux" in image.interpreter
    assert "libc.so.6" in image.needed_libraries
    assert image.linked_libc == "libc.so.6"
    assert image.linking == "dynamic"
    assert image.build_id
    assert image.runpath == ["/opt/pwnpilot-test"]
    assert any(symbol.name == "puts" for symbol in image.imports)
    assert any(symbol.name == "main" for symbol in image.exports)
    assert image.relocations
    assert any(item.symbol == "puts" for item in image.relocations)


def test_dynamic_got_and_plt_are_derived_from_relocations(dynamic_fixture: bytes):
    report = analyze_got_plt(parse_elf(dynamic_fixture))

    puts_got = [entry for entry in report.got_entries if entry.symbol == "puts"]
    puts_plt = [entry for entry in report.plt_entries if entry.symbol == "puts"]
    assert puts_got and puts_got[0].verification == "verified"
    assert puts_plt and puts_plt[0].address is not None
    assert puts_plt[0].verification == "inferred"
    assert puts_plt[0].got_address == puts_got[0].address


def test_detailed_checksec_reports_evidence(dynamic_fixture: bytes):
    report = run_checksec(parse_elf(dynamic_fixture))
    details = {item.name: item for item in report.protections}

    assert report.nx is True
    assert report.pie == "PIE"
    assert report.relro == "Full"
    assert report.canary is True
    assert report.fortify is True
    assert report.runpath is True
    assert details["nx"].verification == "verified"
    assert details["stack_canary"].evidence
    assert details["relro"].confidence == 1.0
    assert details["pie"].possible_strategies
    assert details["ibt"].enabled is True
    assert details["shadow_stack"].enabled is True


def test_attack_surface_includes_call_site_and_argument_evidence(
    dynamic_fixture: bytes,
):
    findings = scan_vulns(parse_elf(dynamic_fixture))
    strcpy = next(item for item in findings if item.symbol == "strcpy")

    assert strcpy.status == "possible"
    assert strcpy.verification == "inferred"
    assert strcpy.call_sites
    assert strcpy.call_sites[0].function == "inspect_argument"
    assert strcpy.call_sites[0].calling_convention == "sysv_amd64"
    assert "rdi" in strcpy.call_sites[0].arguments
    assert strcpy.false_positive_factors


def test_static_linking_is_not_inferred_from_mime(static_fixture: bytes):
    image = parse_elf(static_fixture)
    report = run_checksec(image)

    assert image.interpreter is None
    assert image.needed_libraries == []
    assert image.linking == "static"
    assert report.static is True
    static_detail = next(
        item for item in report.protections if item.name == "static_linking"
    )
    assert static_detail.verification == "verified"


def test_phase2_api_contracts(client, dynamic_fixture: bytes):
    uploaded = client.post(
        "/api/v1/binaries",
        files={"file": ("protected.elf", dynamic_fixture, "application/octet-stream")},
    )
    assert uploaded.status_code == 200
    binary_id = uploaded.json()["binary_id"]

    metadata = client.get(f"/api/v1/binaries/{binary_id}/elf")
    assert metadata.status_code == 200
    assert metadata.json()["linked_libc"] == "libc.so.6"
    assert metadata.json()["linking"] == "dynamic"

    imports = client.get(
        f"/api/v1/binaries/{binary_id}/imports", params={"offset": 0, "limit": 2}
    )
    assert imports.status_code == 200
    assert imports.json()["limit"] == 2
    assert imports.json()["total"] >= len(imports.json()["items"])

    symbols = client.get(
        f"/api/v1/binaries/{binary_id}/symbols",
        params={"kind": "dynamic", "offset": 0, "limit": 10},
    )
    exports = client.get(f"/api/v1/binaries/{binary_id}/exports")
    functions = client.get(f"/api/v1/binaries/{binary_id}/functions")
    assert symbols.status_code == 200 and symbols.json()["items"]
    assert any(item["name"] == "main" for item in exports.json()["items"])
    assert any(item["name"] == "inspect_argument" for item in functions.json()["items"])
    assert (
        client.get(
            f"/api/v1/binaries/{binary_id}/symbols", params={"limit": 5001}
        ).status_code
        == 422
    )

    relocations = client.get(
        f"/api/v1/binaries/{binary_id}/relocations",
        params={"offset": 0, "limit": 5},
    )
    assert relocations.status_code == 200
    assert relocations.json()["total"] > 0

    got = client.get(f"/api/v1/binaries/{binary_id}/got")
    plt = client.get(f"/api/v1/binaries/{binary_id}/plt")
    libraries = client.get(f"/api/v1/binaries/{binary_id}/libraries")
    assert got.status_code == 200 and got.json()["entries"]
    assert plt.status_code == 200 and plt.json()["items"]
    assert libraries.json()["verification"] == "verified"

    analysis = client.post(f"/api/v1/binaries/{binary_id}/analyze")
    assert analysis.status_code == 202
    assert analysis.json()["analyzer_version"] == "2.0.0"
    assert analysis.json()["result"]["elf"]["relocation_count"] > 0
    assert analysis.json()["result"]["checksec"]["protections"]
