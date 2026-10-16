#!/usr/bin/env python3
"""Qualify policy- or source-selected RISC-V IRQ sites via Linux Kbuild.

The caller must source the kernel workspace's host-tool environment first.
This driver never runs a clean target.  To make map selection changes visible
to Kbuild, it removes only kernel/softirq.o and its exact dependency/command
records before rebuilding that object.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
from types import SimpleNamespace

from test_map_plugin import (
    MAP_SECTIONS,
    elf_inertness_fingerprint,
    require_inertness,
)


HERE = pathlib.Path(__file__).resolve().parent
TOOL = HERE.parent
DEFAULT_SPEC = TOOL / "examples" / "riscv-linux-softirq-v1.json"
GIB = 1024 ** 3


def run(command: list[str], *, environment: dict[str, str] | None = None,
        capture: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        env=environment,
        check=True,
        capture_output=capture,
        text=True,
    )


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as input_file:
        while chunk := input_file.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def require_file(path: pathlib.Path, description: str) -> pathlib.Path:
    # Keep the executable spelling supplied by the caller.  In particular,
    # LLVM installs ld.lld as a symlink to the generic lld driver, whose
    # behaviour is selected from argv[0].  Resolving that symlink makes Linux
    # Kbuild invoke the wrong driver even though the selected file exists.
    path = pathlib.Path(os.path.abspath(path))
    if not path.is_file():
        raise ValueError(f"{description} is not a file: {path}")
    return path


def require_build_layout(linux: pathlib.Path, build: pathlib.Path) -> None:
    linux = linux.resolve()
    build = build.resolve()
    require_file(linux / "Makefile", "Linux top-level Makefile")
    require_file(linux / "kernel" / "softirq.c", "Linux softirq source")
    if build == linux or linux in build.parents:
        raise ValueError("the Linux qualification build must be out of tree")


def require_disk(build: pathlib.Path, minimum_gib: float) -> int:
    anchor = build if build.exists() else build.parent
    free = shutil.disk_usage(anchor).free
    if free < minimum_gib * GIB:
        raise RuntimeError(
            f"only {free / GIB:.2f} GiB free at {anchor}; "
            f"qualification requires {minimum_gib:.2f} GiB"
        )
    print(f"disk-free[{anchor}]={free / GIB:.2f} GiB", flush=True)
    return free


def make_command(arguments: argparse.Namespace, target: str,
                 *, plugin: bool, source_site: bool = False) -> list[str]:
    command = [
        arguments.make,
        "-C", str(arguments.linux),
        "LLVM=1",
        f"O={arguments.build}",
        "ARCH=riscv",
        "CROSS_COMPILE=riscv64-linux-gnu-",
        f"CC={arguments.clang} --target=riscv64-linux-gnu",
        f"LD={arguments.ld_lld}",
        "KBUILD_BUILD_TIMESTAMP=2026-10-16T00:00:00Z",
        "KBUILD_BUILD_USER=kernel-lab",
        "KBUILD_BUILD_HOST=kernel-lab",
        "KBUILD_BUILD_VERSION=1",
    ]
    host_cflags = os.environ.get("HOSTCFLAGS")
    if host_cflags:
        command.append(f"HOSTCFLAGS={host_cflags}")
    softirq_flags = []
    if arguments.source_sites:
        softirq_flags.extend([
            "-gline-tables-only",
            f"-ffile-prefix-map={arguments.linux}=.",
        ])
    if plugin:
        softirq_flags.append(f"-fpass-plugin={arguments.plugin}")
    if source_site:
        softirq_flags.append("-D__RISCV_LINUX_IRQ_SITE_MAP__")
    if softirq_flags:
        command.append(f"CFLAGS_softirq.o+={' '.join(softirq_flags)}")
    command.extend(["-j1", target])
    return command


def force_softirq_rebuild(build: pathlib.Path) -> None:
    kernel = build.resolve() / "kernel"
    for name in ("softirq.o", ".softirq.o.cmd", ".softirq.o.d"):
        candidate = kernel / name
        if candidate.is_symlink() or candidate.is_file():
            candidate.unlink()
        elif candidate.exists():
            raise RuntimeError(
                f"refusing to remove non-file Kbuild artifact {candidate}"
            )


def build_variant(arguments: argparse.Namespace, name: str, *, plugin: bool,
                  spec: pathlib.Path | None, target: str,
                  artifacts: pathlib.Path,
                  source_site: bool = False) -> dict[str, pathlib.Path]:
    require_disk(arguments.build, arguments.min_free_gib)
    force_softirq_rebuild(arguments.build)
    environment = os.environ.copy()
    if spec is None:
        environment.pop("CLANG_KERNEL_LAB_MAP_SPEC", None)
    else:
        environment["CLANG_KERNEL_LAB_MAP_SPEC"] = str(spec)
    print(f"building Linux {name} target={target} with -j1", flush=True)
    run(
        make_command(
            arguments, target, plugin=plugin, source_site=source_site
        ),
        environment=environment,
        capture=False,
    )

    products = {
        "object": arguments.build / "kernel" / "softirq.o",
    }
    if target == "vmlinux":
        products.update({
            "vmlinux": arguments.build / "vmlinux",
            "vmlinux_unstripped": arguments.build / "vmlinux.unstripped",
            "system_map": arguments.build / "System.map",
        })
    copied = {}
    for key, source in products.items():
        source = require_file(source, f"Kbuild {key}")
        destination = artifacts / f"{name}-{source.name}"
        shutil.copy2(source, destination)
        copied[key] = destination
    return copied


def decode_sites(arguments: argparse.Namespace, artifact: pathlib.Path,
                 *, relocatable: bool,
                 expected_kinds: list[int]) -> dict[str, object]:
    command = [str(arguments.site_tool)]
    if relocatable:
        command.append("--validate-relocatable")
    command.append(str(artifact))
    document = json.loads(run(command).stdout)
    kinds = sorted(site["kind"] for site in document["sites"])
    if kinds != expected_kinds:
        raise AssertionError(
            f"{artifact} has site kinds {kinds}, expected {expected_kinds}"
        )
    return document


def site_ids(document: dict[str, object]) -> list[str]:
    return sorted(site["site_id"] for site in document["sites"])


def partial_link(arguments: argparse.Namespace, linker: pathlib.Path,
                 linker_name: str, variants: dict[str, dict[str, pathlib.Path]],
                 artifacts: pathlib.Path) -> dict[str, object]:
    outputs = {}
    for variant in ("baseline", "disabled", "mapped"):
        output = artifacts / f"{linker_name}-{variant}-softirq.o"
        run([
            str(linker), "-r", "-m", "elf64lriscv",
            str(variants[variant]["object"]), "-o", str(output),
        ])
        outputs[variant] = output

    inertness_arguments = SimpleNamespace(
        llvm_readobj=str(arguments.llvm_readobj)
    )
    require_inertness(
        inertness_arguments,
        outputs["baseline"],
        outputs["disabled"],
        f"Linux Kbuild {linker_name} partial-link disabled plugin",
    )
    require_inertness(
        inertness_arguments,
        outputs["baseline"],
        outputs["mapped"],
        f"Linux Kbuild {linker_name} partial-link map",
    )
    mapped_document = decode_sites(
        arguments, outputs["mapped"], relocatable=True,
        expected_kinds=arguments.expected_kinds,
    )
    return {
        "result": "PASS",
        "mapped_sha256": sha256(outputs["mapped"]),
        "site_ids": site_ids(mapped_document),
    }


def program_headers(arguments: argparse.Namespace,
                    artifact: pathlib.Path) -> list[dict[str, object]]:
    document = json.loads(run([
        str(arguments.llvm_readobj),
        "--elf-output-style=JSON",
        "--program-headers",
        str(artifact),
    ]).stdout)[0]
    return [entry["ProgramHeader"] for entry in document["ProgramHeaders"]]


def riscv_attributes(arguments: argparse.Namespace,
                     artifact: pathlib.Path) -> tuple[dict[str, object], int]:
    document = json.loads(run([
        str(arguments.llvm_readobj),
        "--elf-output-style=JSON",
        "--sections",
        "--section-data",
        str(artifact),
    ]).stdout)[0]
    matches = [
        entry["Section"] for entry in document["Sections"]
        if entry["Section"]["Name"]["Name"] == ".riscv.attributes"
    ]
    if len(matches) != 1:
        raise AssertionError(
            f"{artifact} has {len(matches)} .riscv.attributes sections"
        )
    section = matches[0]
    identity = {
        "type": section["Type"],
        "flags": section["Flags"],
        "address": section["Address"],
        "size": section["Size"],
        "link": section["Link"],
        "info": section["Info"],
        "alignment": section["AddressAlignment"],
        "entry_size": section["EntrySize"],
        "data": section.get("SectionData", {}).get("Bytes", []),
    }
    return identity, section["Offset"]


def require_program_header_inertness(
        arguments: argparse.Namespace, baseline: pathlib.Path,
        mapped: pathlib.Path, description: str) -> dict[str, object]:
    def normalize(headers: list[dict[str, object]]) \
            -> tuple[list[dict[str, object]], int]:
        normalized = []
        attribute_offsets = []
        for original in headers:
            header = dict(original)
            if header["Type"]["Name"] == "PT_RISCV_ATTRIBUTES":
                attribute_offsets.append(header.pop("Offset"))
            normalized.append(header)
        if len(attribute_offsets) != 1:
            raise AssertionError(
                f"{description} has {len(attribute_offsets)} "
                "PT_RISCV_ATTRIBUTES headers"
            )
        return normalized, attribute_offsets[0]

    baseline_headers, baseline_offset = normalize(
        program_headers(arguments, baseline)
    )
    mapped_headers, mapped_offset = normalize(
        program_headers(arguments, mapped)
    )
    if baseline_headers != mapped_headers:
        raise AssertionError(f"{description} program headers changed")

    baseline_attributes, baseline_section_offset = riscv_attributes(
        arguments, baseline
    )
    mapped_attributes, mapped_section_offset = riscv_attributes(
        arguments, mapped
    )
    if baseline_attributes != mapped_attributes:
        raise AssertionError(f"{description} RISC-V attributes changed")
    if baseline_offset != baseline_section_offset or \
            mapped_offset != mapped_section_offset:
        raise AssertionError(
            f"{description} PT_RISCV_ATTRIBUTES does not cover its section"
        )
    return {
        "runtime_headers": "identical",
        "riscv_attributes": "identical",
        "baseline_attributes_offset": baseline_offset,
        "mapped_attributes_offset": mapped_offset,
    }


def require_map_sections_nonalloc(arguments: argparse.Namespace,
                                  artifact: pathlib.Path) -> None:
    document = json.loads(run([
        str(arguments.llvm_readobj),
        "--elf-output-style=JSON",
        "--sections",
        str(artifact),
    ]).stdout)[0]
    found = set()
    for entry in document["Sections"]:
        section = entry["Section"]
        name = section["Name"]["Name"]
        if name not in MAP_SECTIONS:
            continue
        found.add(name)
        flags = {item["Name"] for item in section["Flags"]["Flags"]}
        if "SHF_ALLOC" in flags:
            raise AssertionError(
                f"linked map section {name} remains runtime allocated"
            )
    expected = {
        ".riscv.linux_irq_c_sites",
        ".riscv.linux_irq_expected",
    }
    if found != expected:
        raise AssertionError(
            f"linked map sections are {sorted(found)}, expected {sorted(expected)}"
        )


def normalized_notes(arguments: argparse.Namespace,
                     artifact: pathlib.Path) -> tuple[list[object], str]:
    document = json.loads(run([
        str(arguments.llvm_readobj),
        "--elf-output-style=JSON",
        "--notes",
        str(artifact),
    ]).stdout)[0]
    normalized = []
    build_ids = []
    for entry in document.get("NoteSections", []):
        section = entry["NoteSection"]
        normalized_section = {
            key: value for key, value in section.items() if key != "Notes"
        }
        normalized_section["Notes"] = []
        for original_note in section["Notes"]:
            note = dict(original_note)
            if note.get("Owner") == "GNU" and \
                    str(note.get("Type", "")).startswith("NT_GNU_BUILD_ID"):
                build_id = note.get("Build ID", "")
                try:
                    build_id_bytes = bytes.fromhex(build_id)
                except ValueError as error:
                    raise AssertionError(
                        f"invalid GNU build ID in {artifact}: {build_id!r}"
                    ) from error
                if note.get("Data size") != len(build_id_bytes) or \
                        not build_id_bytes:
                    raise AssertionError(
                        f"invalid GNU build ID size in {artifact}"
                    )
                build_ids.append(build_id)
                note["Build ID"] = "<normalized-build-id>"
            normalized_section["Notes"].append(note)
        normalized.append({"NoteSection": normalized_section})
    if len(build_ids) != 1:
        raise AssertionError(
            f"{artifact} has {len(build_ids)} GNU build IDs, expected one"
        )
    return normalized, build_ids[0]


def require_vmlinux_map_inertness(
        arguments: argparse.Namespace, baseline: pathlib.Path,
        mapped: pathlib.Path, description: str) -> dict[str, str]:
    baseline_fingerprint = elf_inertness_fingerprint(arguments, baseline)
    mapped_fingerprint = elf_inertness_fingerprint(arguments, mapped)
    for component in baseline_fingerprint:
        baseline_value = baseline_fingerprint[component]
        mapped_value = mapped_fingerprint[component]
        if component == "allocated_sections":
            baseline_value = [
                section for section in baseline_value
                if section[0] != ".notes"
            ]
            mapped_value = [
                section for section in mapped_value
                if section[0] != ".notes"
            ]
        if baseline_value != mapped_value:
            raise AssertionError(
                f"{description} changed ELF inertness component {component}"
            )

    baseline_notes, baseline_build_id = normalized_notes(
        arguments, baseline
    )
    mapped_notes, mapped_build_id = normalized_notes(arguments, mapped)
    if baseline_notes != mapped_notes:
        raise AssertionError(
            f"{description} changed an ELF note other than the GNU build ID"
        )
    return {
        "baseline": baseline_build_id,
        "mapped": mapped_build_id,
        "relation": (
            "identical" if baseline_build_id == mapped_build_id
            else "metadata-hash-only change"
        ),
    }


def qualify_vmlinux(arguments: argparse.Namespace,
                    variants: dict[str, dict[str, pathlib.Path]]) \
        -> dict[str, object]:
    inertness_arguments = SimpleNamespace(
        llvm_readobj=str(arguments.llvm_readobj)
    )
    build_ids = {}
    header_results = {}
    for image_key in ("vmlinux", "vmlinux_unstripped"):
        require_inertness(
            inertness_arguments,
            variants["baseline"][image_key],
            variants["disabled"][image_key],
            f"Linux {image_key} disabled plugin",
        )
        build_ids[image_key] = require_vmlinux_map_inertness(
            inertness_arguments,
            variants["baseline"][image_key],
            variants["mapped"][image_key],
            f"Linux {image_key} map",
        )
        header_results[image_key] = require_program_header_inertness(
            arguments,
            variants["baseline"][image_key],
            variants["mapped"][image_key],
            f"Linux {image_key}",
        )
        require_map_sections_nonalloc(
            arguments, variants["mapped"][image_key]
        )

    if variants["baseline"]["system_map"].read_bytes() != \
            variants["mapped"]["system_map"].read_bytes():
        raise AssertionError("map mode changed System.map")
    linked_document = decode_sites(
        arguments, variants["mapped"]["vmlinux"], relocatable=False,
        expected_kinds=arguments.expected_kinds,
    )
    return {
        "result": "PASS",
        "site_ids": site_ids(linked_document),
        "sites": linked_document["sites"],
        "map_sections": "non-alloc",
        "gnu_build_ids": build_ids,
        "program_headers": header_results,
        "system_map": "identical",
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--linux", required=True, type=pathlib.Path)
    parser.add_argument("--build", required=True, type=pathlib.Path)
    parser.add_argument("--clang", required=True, type=pathlib.Path)
    parser.add_argument("--ld-lld", required=True, type=pathlib.Path)
    parser.add_argument("--gnu-ld", type=pathlib.Path)
    parser.add_argument("--llvm-readobj", required=True, type=pathlib.Path)
    parser.add_argument("--plugin", required=True, type=pathlib.Path)
    parser.add_argument("--site-tool", required=True, type=pathlib.Path)
    parser.add_argument("--make", default="make")
    parser.add_argument("--spec", type=pathlib.Path, default=DEFAULT_SPEC)
    parser.add_argument("--configure-tiny", action="store_true")
    parser.add_argument("--full-vmlinux", action="store_true")
    parser.add_argument(
        "--source-sites",
        action="store_true",
        help="qualify the opt-in Linux source wrapper instead of policy rules",
    )
    parser.add_argument("--min-free-gib", type=float, default=1.0)
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    arguments.linux = arguments.linux.resolve()
    arguments.build = arguments.build.resolve()
    arguments.clang = require_file(arguments.clang, "Clang")
    arguments.ld_lld = require_file(arguments.ld_lld, "LLD")
    if arguments.gnu_ld:
        arguments.gnu_ld = require_file(arguments.gnu_ld, "GNU ld")
    arguments.llvm_readobj = require_file(
        arguments.llvm_readobj, "llvm-readobj"
    )
    arguments.plugin = require_file(arguments.plugin, "map plugin")
    arguments.site_tool = require_file(arguments.site_tool, "site tool")
    if arguments.source_sites:
        arguments.spec = None
    else:
        arguments.spec = require_file(
            arguments.spec, "softirq map specification"
        )
    arguments.expected_kinds = [11] if arguments.source_sites else [10, 11]
    if arguments.min_free_gib <= 0:
        raise ValueError("--min-free-gib must be positive")
    require_build_layout(arguments.linux, arguments.build)

    if arguments.configure_tiny:
        arguments.build.mkdir(parents=True, exist_ok=True)
        require_disk(arguments.build, arguments.min_free_gib)
        environment = os.environ.copy()
        environment.pop("CLANG_KERNEL_LAB_MAP_SPEC", None)
        print("configuring Linux tinyconfig with -j1", flush=True)
        run(
            make_command(arguments, "tinyconfig", plugin=False),
            environment=environment,
            capture=False,
        )
    elif not (arguments.build / ".config").is_file():
        raise ValueError(
            "the build has no .config; pass --configure-tiny explicitly"
        )

    target = "vmlinux" if arguments.full_vmlinux else "kernel/softirq.o"
    with tempfile.TemporaryDirectory(
            prefix="kernel-lab-linux-softirq-") as temporary:
        artifacts = pathlib.Path(temporary)
        variants = {
            "baseline": build_variant(
                arguments, "baseline", plugin=False, spec=None,
                target=target, artifacts=artifacts,
            ),
            "disabled": build_variant(
                arguments, "disabled", plugin=True, spec=None,
                target=target, artifacts=artifacts,
            ),
            "mapped": build_variant(
                arguments, "mapped", plugin=True, spec=arguments.spec,
                target=target, artifacts=artifacts,
                source_site=arguments.source_sites,
            ),
        }

        inertness_arguments = SimpleNamespace(
            llvm_readobj=str(arguments.llvm_readobj)
        )
        require_inertness(
            inertness_arguments,
            variants["baseline"]["object"],
            variants["disabled"]["object"],
            "Linux Kbuild disabled plugin object",
        )
        if variants["baseline"]["object"].read_bytes() != \
                variants["disabled"]["object"].read_bytes():
            raise AssertionError(
                "disabled map plugin object is not byte-identical"
            )
        require_inertness(
            inertness_arguments,
            variants["baseline"]["object"],
            variants["mapped"]["object"],
            "Linux Kbuild softirq map object",
        )
        object_document = decode_sites(
            arguments, variants["mapped"]["object"], relocatable=True,
            expected_kinds=arguments.expected_kinds,
        )

        results: dict[str, object] = {
            "result": "PASS",
            "linux_revision": run([
                "git", "-C", str(arguments.linux), "rev-parse", "HEAD"
            ]).stdout.strip(),
            "config_sha256": sha256(arguments.build / ".config"),
            "build_jobs": 1,
            "selection_mode": (
                "source-wrapper" if arguments.source_sites else "policy"
            ),
            "softirq_object": {
                "result": "PASS",
                "disabled_byte_identity": "PASS",
                "inertness": "PASS",
                "site_ids": site_ids(object_document),
                "sites": object_document["sites"],
            },
            "lld_partial_link": partial_link(
                arguments, arguments.ld_lld, "lld", variants, artifacts
            ),
        }
        if arguments.gnu_ld:
            results["gnu_partial_link"] = partial_link(
                arguments, arguments.gnu_ld, "gnu", variants, artifacts
            )
        else:
            results["gnu_partial_link"] = {"result": "not-requested"}
        if arguments.full_vmlinux:
            results["vmlinux"] = qualify_vmlinux(arguments, variants)
        else:
            results["vmlinux"] = {"result": "not-requested"}

        expected_ids = results["softirq_object"]["site_ids"]
        if results["lld_partial_link"]["site_ids"] != expected_ids:
            raise AssertionError("LLD partial link changed softirq site IDs")
        if arguments.gnu_ld and \
                results["gnu_partial_link"]["site_ids"] != expected_ids:
            raise AssertionError("GNU partial link changed softirq site IDs")
        if arguments.full_vmlinux and \
                results["vmlinux"]["site_ids"] != expected_ids:
            raise AssertionError("vmlinux link changed softirq site IDs")

        results["free_bytes_after"] = require_disk(
            arguments.build, arguments.min_free_gib
        )
        print(json.dumps(results, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
