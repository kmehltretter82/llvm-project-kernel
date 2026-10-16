#!/usr/bin/env python3
"""Prove the late C map pass is text-inert and coverage-checked."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tempfile


HERE = pathlib.Path(__file__).resolve().parent
TOOL = HERE.parent
ROOT = TOOL.parents[2]
SOURCE = HERE / "map-probe.c"
LTO_SITE_SOURCE = HERE / "map-lto-site.c"
LTO_CALLER_SOURCE = HERE / "map-lto-caller.c"
LTO_MULTI_CALLER_SOURCE = HERE / "map-lto-multi-caller.c"
LINKER_SCRIPT = HERE / "map-link.ld"
VALID_SPEC = TOOL / "examples" / "riscv-map-v1.json"
GAP_SPEC = TOOL / "examples" / "riscv-map-coverage-gap-v1.json"
CROSS_TU_SPEC = TOOL / "examples" / "riscv-map-cross-tu-v1.json"
MAP_SECTIONS = {
    ".riscv.linux_irq_c_sites",
    ".riscv.linux_irq_expected",
    ".riscv.linux_irq_sites",
}
UNWIND_SECTIONS = {
    ".ARM.exidx",
    ".ARM.extab",
    ".debug_frame",
    ".eh_frame",
    ".orc_unwind",
    ".orc_unwind_ip",
    ".sframe",
}


def run(command: list[str], *, environment: dict[str, str] | None = None,
        check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        env=environment,
        check=check,
        capture_output=True,
        text=True,
    )


def compile_object(arguments: argparse.Namespace, output: pathlib.Path,
                   *, plugin: bool, spec: pathlib.Path | None,
                   global_isel: bool = False,
                   source_site: bool = False,
                   thin_lto: bool = False,
                   split_dwarf: bool = False,
                   optimization: str = "2",
                   debug_info: bool = True,
                   check: bool = True,
                   source: pathlib.Path = SOURCE,
                   prefix_root: pathlib.Path = ROOT,
                   relax: bool = True,
                   ) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    if spec is None:
        environment.pop("CLANG_KERNEL_LAB_MAP_SPEC", None)
    else:
        environment["CLANG_KERNEL_LAB_MAP_SPEC"] = str(spec)
    command = [
        arguments.clang,
        "--target=riscv64-unknown-linux-gnu",
        "-march=rv64ima",
        "-mabi=lp64",
        "-mcmodel=medany",
        f"-O{optimization}",
        "-ffreestanding",
        "-fno-addrsig",
        f"-ffile-prefix-map={prefix_root}=.",
    ]
    if split_dwarf and not debug_info:
        raise ValueError("split DWARF requires debug information")
    if debug_info:
        command.append("-g" if split_dwarf else "-gline-tables-only")
    if split_dwarf:
        command.append("-gsplit-dwarf")
    if not relax:
        command.append("-mno-relax")
    if global_isel:
        command.extend(["-fglobal-isel", "-Wno-global-isel"])
    if thin_lto:
        command.append("-flto=thin")
    if source_site:
        command.append("-DKERNEL_LAB_SOURCE_SITE=1")
    if plugin:
        command.append(f"-fpass-plugin={arguments.plugin.resolve()}")
    command.extend(["-c", str(source), "-o", str(output)])
    return run(command, environment=environment, check=check)


def link(arguments: argparse.Namespace,
         obj: pathlib.Path | list[pathlib.Path],
         output: pathlib.Path, *, gc_sections: bool = False,
         entry: str = "irq_map_probe", linker: str | None = None) -> None:
    objects = [obj] if isinstance(obj, pathlib.Path) else obj
    command = [
        linker or arguments.ld_lld,
        "-m", "elf64lriscv",
        "-e", entry,
        "-T", str(LINKER_SCRIPT),
    ]
    command.extend(str(item) for item in objects)
    command.extend(["-o", str(output)])
    if gc_sections:
        command.append("--gc-sections")
    run(command)


def dump_section(arguments: argparse.Namespace, binary: pathlib.Path,
                 section: str, output: pathlib.Path) -> bytes:
    run([
        arguments.llvm_objcopy,
        f"--dump-section={section}={output}",
        str(binary),
    ])
    return output.read_bytes()


def elf_inertness_fingerprint(arguments: argparse.Namespace,
                              binary: pathlib.Path) -> dict[str, object]:
    document = json.loads(run([
        arguments.llvm_readobj,
        "--elf-output-style=JSON",
        "--sections",
        "--section-data",
        "--symbols",
        "--relocations",
        str(binary),
    ]).stdout)[0]
    sections = [entry["Section"] for entry in document["Sections"]]
    by_index = {section["Index"]: section for section in sections}

    def section_name(section: dict[str, object]) -> str:
        return section["Name"]["Name"]

    def section_flags(section: dict[str, object]) -> tuple[str, ...]:
        return tuple(sorted(
            flag["Name"] for flag in section["Flags"]["Flags"]
        ))

    def section_bytes(section: dict[str, object]) -> tuple[int, ...]:
        return tuple(section.get("SectionData", {}).get("Bytes", []))

    allocated_sections = []
    executable_sections = []
    unwind_sections = []
    for section in sections:
        name = section_name(section)
        flags = section_flags(section)
        normalized = (
            name,
            section["Type"]["Name"],
            flags,
            section["Address"],
            section["Size"],
            section["AddressAlignment"],
            section["EntrySize"],
            section_bytes(section),
        )
        if "SHF_ALLOC" in flags and name not in MAP_SECTIONS:
            allocated_sections.append(normalized)
        if "SHF_EXECINSTR" in flags:
            executable_sections.append(normalized)
        if name in UNWIND_SECTIONS:
            unwind_sections.append(normalized)

    symbols = []
    for entry in document.get("Symbols", []):
        symbol = entry["Symbol"]
        binding = symbol["Binding"]["Name"]
        symbol_type = symbol["Type"]["Name"]
        target_section = symbol["Section"]["Name"]
        if target_section in MAP_SECTIONS:
            continue
        if binding == "Local" and symbol_type not in ("Function", "Object"):
            continue
        symbols.append((
            symbol["Name"]["Name"],
            symbol["Value"],
            symbol["Size"],
            binding,
            symbol_type,
            symbol["Other"]["Value"],
            target_section,
        ))

    relocation_targets = {}
    for section in sections:
        if section["Type"]["Name"] not in ("SHT_REL", "SHT_RELA"):
            continue
        target = by_index.get(section["Info"])
        if target is not None:
            relocation_targets[section["Index"]] = section_name(target)

    code_relocations = []
    unwind_relocations = []
    for group in document.get("Relocations", []):
        target = relocation_targets.get(group["SectionIndex"])
        if target is None:
            continue
        relocation_section = by_index[group["SectionIndex"]]
        target_section = by_index[relocation_section["Info"]]
        normalized_relocations = []
        for entry in group["Relocs"]:
            relocation = entry["Relocation"]
            normalized_relocations.append((
                relocation["Offset"],
                relocation["Type"]["Name"],
                relocation["Symbol"]["Name"],
                relocation.get("Addend", 0),
            ))
        if "SHF_EXECINSTR" in section_flags(target_section):
            code_relocations.extend((target, *item)
                                    for item in normalized_relocations)
        if target in UNWIND_SECTIONS:
            unwind_relocations.extend((target, *item)
                                      for item in normalized_relocations)

    return {
        "allocated_sections": sorted(allocated_sections),
        "executable_sections": sorted(executable_sections),
        "symbols": sorted(symbols),
        "code_relocations": sorted(code_relocations),
        "unwind_sections": sorted(unwind_sections),
        "unwind_relocations": sorted(unwind_relocations),
    }


def require_inertness(arguments: argparse.Namespace, baseline: pathlib.Path,
                       mapped: pathlib.Path, description: str) -> None:
    baseline_fingerprint = elf_inertness_fingerprint(arguments, baseline)
    mapped_fingerprint = elf_inertness_fingerprint(arguments, mapped)
    for component in baseline_fingerprint:
        if baseline_fingerprint[component] != mapped_fingerprint[component]:
            raise AssertionError(
                f"{description} changed ELF inertness component {component}"
            )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clang", required=True)
    parser.add_argument("--ld-lld", required=True)
    parser.add_argument(
        "--gnu-ld",
        help="optional GNU RISC-V linker for the non-LTO compatibility lane",
    )
    parser.add_argument("--llvm-objcopy", required=True)
    parser.add_argument("--llvm-readobj", required=True)
    parser.add_argument("--plugin", required=True, type=pathlib.Path)
    parser.add_argument("--site-tool", required=True, type=pathlib.Path)
    parser.add_argument(
        "--selectiondag-expect",
        choices=("loss", "complete"),
        default="loss",
        help="expected handling of the four-site SelectionDAG fixture",
    )
    parser.add_argument(
        "--global-isel-expect",
        choices=("loss", "complete"),
        default="complete",
        help="expected handling of the four-site experimental GlobalISel fixture",
    )
    parser.add_argument(
        "--source-builtin-expect",
        choices=("unavailable", "complete"),
        default="unavailable",
        help="whether this Clang provides the experimental source builtin",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    source_builtin = arguments.source_builtin_expect == "complete"
    with tempfile.TemporaryDirectory(prefix="clang-kernel-lab-map-") as temp:
        directory = pathlib.Path(temp)
        baseline_obj = directory / "baseline.o"
        disabled_obj = directory / "disabled.o"
        mapped_obj = directory / "mapped.o"
        source_obj = directory / "source.o"
        gap_obj = directory / "gap.o"
        gisel_baseline_obj = directory / "gisel-baseline.o"
        gisel_mapped_obj = directory / "gisel-mapped.o"

        compile_object(arguments, baseline_obj, plugin=False, spec=None)
        compile_object(arguments, disabled_obj, plugin=True, spec=None)
        mapped_compile = compile_object(
            arguments, mapped_obj, plugin=True, spec=VALID_SPEC
        )
        source_compile = None
        if source_builtin:
            source_compile = compile_object(
                arguments, source_obj, plugin=True, spec=None, source_site=True
            )
        if "loosing !pcsections" in mapped_compile.stderr:
            raise AssertionError(
                f"qualified map unexpectedly lost metadata: {mapped_compile.stderr}"
            )
        if source_compile and "loosing !pcsections" in source_compile.stderr:
            raise AssertionError(
                f"source marker unexpectedly lost metadata: "
                f"{source_compile.stderr}"
            )

        baseline_obj_text = dump_section(
            arguments, baseline_obj, ".text", directory / "baseline-o.text"
        )
        disabled_obj_text = dump_section(
            arguments, disabled_obj, ".text", directory / "disabled-o.text"
        )
        mapped_obj_text = dump_section(
            arguments, mapped_obj, ".text", directory / "mapped-o.text"
        )
        if baseline_obj_text != disabled_obj_text:
            raise AssertionError("loading disabled map plugin changed object .text")
        if baseline_obj_text != mapped_obj_text:
            raise AssertionError("enabled C map changed object .text")
        require_inertness(
            arguments, baseline_obj, disabled_obj, "disabled object map"
        )
        require_inertness(
            arguments, baseline_obj, mapped_obj, "policy object map"
        )
        if source_builtin:
            source_obj_text = dump_section(
                arguments, source_obj, ".text", directory / "source-o.text"
            )
            if baseline_obj_text != source_obj_text:
                raise AssertionError("source builtin map changed object .text")
            require_inertness(
                arguments, baseline_obj, source_obj, "source object map"
            )

        object_result = run([
            str(arguments.site_tool.resolve()),
            "--validate-relocatable",
            str(mapped_obj),
        ])
        object_map = json.loads(object_result.stdout)
        if object_map["artifact_kind"] != "relocatable-object":
            raise AssertionError("C map object has the wrong artifact kind")
        if len(object_map["sites"]) != 1:
            raise AssertionError("C map object does not contain exactly one site")
        object_site = object_map["sites"][0]
        if object_site["relocation_type"] != (
            "R_RISCV_ADD64+R_RISCV_SUB64"
        ):
            raise AssertionError("C carrier has the wrong relocation pair")
        if object_site["text_section"] != ".text":
            raise AssertionError("C carrier relocation does not target .text")

        source_optimization_levels: dict[str, str] = {}
        if source_builtin:
            source_object_map = json.loads(run([
                str(arguments.site_tool.resolve()),
                "--validate-relocatable",
                str(source_obj),
            ]).stdout)
            if len(source_object_map["sites"]) != 1:
                raise AssertionError(
                    "source builtin did not emit exactly one site"
                )
            if source_object_map["sites"][0]["kind"] != 39:
                raise AssertionError("source builtin emitted the wrong site kind")

            relocated_root = directory / "relocated-root"
            relocated_source = relocated_root / SOURCE.relative_to(ROOT)
            relocated_source.parent.mkdir(parents=True)
            shutil.copyfile(SOURCE, relocated_source)
            relocated_obj = directory / "source-relocated.o"
            compile_object(
                arguments,
                relocated_obj,
                plugin=True,
                spec=None,
                source_site=True,
                source=relocated_source,
                prefix_root=relocated_root,
            )
            relocated_map = json.loads(run([
                str(arguments.site_tool.resolve()),
                "--validate-relocatable",
                str(relocated_obj),
            ]).stdout)
            if (
                relocated_map["sites"][0]["site_id"]
                != source_object_map["sites"][0]["site_id"]
            ):
                raise AssertionError(
                    "source builtin ID changed across prefix-mapped roots"
                )

            no_debug = compile_object(
                arguments,
                directory / "source-no-debug.o",
                plugin=True,
                spec=None,
                source_site=True,
                debug_info=False,
                check=False,
            )
            if no_debug.returncode == 0:
                raise AssertionError(
                    "source builtin unexpectedly accepted missing line tables"
                )
            if "source markers require line-table debug information" not in (
                no_debug.stderr
            ):
                raise AssertionError(
                    f"unexpected missing-line-table error: {no_debug.stderr!r}"
                )

            source_optimization_levels["O2"] = "PASS"
            for level in ("0", "1", "3", "s", "z"):
                level_baseline = directory / f"source-base-O{level}.o"
                level_source = directory / f"source-map-O{level}.o"
                compile_object(
                    arguments,
                    level_baseline,
                    plugin=False,
                    spec=None,
                    optimization=level,
                )
                compile_object(
                    arguments,
                    level_source,
                    plugin=True,
                    spec=None,
                    source_site=True,
                    optimization=level,
                )
                baseline_text = dump_section(
                    arguments,
                    level_baseline,
                    ".text",
                    directory / f"source-base-O{level}.text",
                )
                source_text = dump_section(
                    arguments,
                    level_source,
                    ".text",
                    directory / f"source-map-O{level}.text",
                )
                if baseline_text != source_text:
                    raise AssertionError(
                        f"source builtin changed object .text at -O{level}"
                    )
                require_inertness(
                    arguments,
                    level_baseline,
                    level_source,
                    f"source object map at -O{level}",
                )
                level_map = json.loads(run([
                    str(arguments.site_tool.resolve()),
                    "--validate-relocatable",
                    str(level_source),
                ]).stdout)
                if len(level_map["sites"]) != 1:
                    raise AssertionError(
                        f"source builtin lost coverage at -O{level}"
                    )
                source_optimization_levels[f"O{level}"] = "PASS"

        baseline_elf = directory / "baseline.elf"
        disabled_elf = directory / "disabled.elf"
        mapped_elf = directory / "mapped.elf"
        source_elf = directory / "source.elf"
        link(arguments, baseline_obj, baseline_elf)
        link(arguments, disabled_obj, disabled_elf)
        link(arguments, mapped_obj, mapped_elf)
        if source_builtin:
            link(arguments, source_obj, source_elf)
        baseline_elf_text = dump_section(
            arguments, baseline_elf, ".text", directory / "baseline-e.text"
        )
        disabled_elf_text = dump_section(
            arguments, disabled_elf, ".text", directory / "disabled-e.text"
        )
        mapped_elf_text = dump_section(
            arguments, mapped_elf, ".text", directory / "mapped-e.text"
        )
        if baseline_elf_text != disabled_elf_text:
            raise AssertionError("loading disabled map plugin changed linked .text")
        if baseline_elf_text != mapped_elf_text:
            raise AssertionError("enabled C map changed linked .text")
        require_inertness(
            arguments, baseline_elf, disabled_elf, "disabled linked map"
        )
        require_inertness(
            arguments, baseline_elf, mapped_elf, "policy linked map"
        )
        if source_builtin:
            source_elf_text = dump_section(
                arguments, source_elf, ".text", directory / "source-e.text"
            )
            if baseline_elf_text != source_elf_text:
                raise AssertionError("source builtin map changed linked .text")
            require_inertness(
                arguments, baseline_elf, source_elf, "source linked map"
            )

        sidecar_result = run([
            str(arguments.site_tool.resolve()),
            "--load-bias=0x1000",
            str(mapped_elf),
        ])
        sidecar = json.loads(sidecar_result.stdout)
        if sidecar["image"]["sha256"] != hashlib.sha256(
            mapped_elf.read_bytes()
        ).hexdigest():
            raise AssertionError("C-map sidecar image digest is incorrect")
        if len(sidecar["sites"]) != 1:
            raise AssertionError(f"unexpected C site count: {sidecar!r}")
        mapped_site = sidecar["sites"][0]
        expected_fields = {
            "carrier": "pcsections",
            "kind": 39,
            "kind_name": "atomic-state-publish",
            "symbol": "irq_map_probe",
        }
        for key, expected in expected_fields.items():
            if mapped_site[key] != expected:
                raise AssertionError(
                    f"unexpected C site {key}: {mapped_site[key]!r}"
                )
        if int(mapped_site["runtime_va"], 0) != int(
            mapped_site["link_va"], 0
        ) + 0x1000:
            raise AssertionError("C site load-bias calculation is incorrect")

        if source_builtin:
            source_sidecar = json.loads(run([
                str(arguments.site_tool.resolve()), str(source_elf)
            ]).stdout)
            if len(source_sidecar["sites"]) != 1:
                raise AssertionError("source builtin linked map is incomplete")
            source_site = source_sidecar["sites"][0]
            if (
                source_site["kind"] != 39
                or source_site["symbol"] != "irq_map_probe"
            ):
                raise AssertionError(
                    f"source builtin linked site is malformed: {source_site!r}"
                )
            if source_site["link_va"] != mapped_site["link_va"]:
                raise AssertionError(
                    "source builtin and policy selector did not anchor the same "
                    "store"
                )

        norelax_baseline_obj = directory / "norelax-baseline.o"
        norelax_mapped_obj = directory / "norelax-mapped.o"
        compile_object(
            arguments,
            norelax_baseline_obj,
            plugin=False,
            spec=None,
            relax=False,
        )
        compile_object(
            arguments,
            norelax_mapped_obj,
            plugin=True,
            spec=VALID_SPEC,
            relax=False,
        )
        require_inertness(
            arguments,
            norelax_baseline_obj,
            norelax_mapped_obj,
            "no-relax policy object map",
        )
        run([
            str(arguments.site_tool.resolve()),
            "--validate-relocatable",
            str(norelax_mapped_obj),
        ])
        norelax_baseline_elf = directory / "norelax-baseline.elf"
        norelax_mapped_elf = directory / "norelax-mapped.elf"
        link(arguments, norelax_baseline_obj, norelax_baseline_elf)
        link(arguments, norelax_mapped_obj, norelax_mapped_elf)
        require_inertness(
            arguments,
            norelax_baseline_elf,
            norelax_mapped_elf,
            "no-relax policy linked map",
        )
        run([str(arguments.site_tool.resolve()), str(norelax_mapped_elf)])
        if source_builtin:
            norelax_source_obj = directory / "norelax-source.o"
            norelax_source_elf = directory / "norelax-source.elf"
            compile_object(
                arguments,
                norelax_source_obj,
                plugin=True,
                spec=None,
                source_site=True,
                relax=False,
            )
            require_inertness(
                arguments,
                norelax_baseline_obj,
                norelax_source_obj,
                "no-relax source object map",
            )
            link(arguments, norelax_source_obj, norelax_source_elf)
            require_inertness(
                arguments,
                norelax_baseline_elf,
                norelax_source_elf,
                "no-relax source linked map",
            )
            run([str(arguments.site_tool.resolve()), str(norelax_source_elf)])

        gc_baseline_elf = directory / "gc-baseline.elf"
        gc_mapped_elf = directory / "gc-mapped.elf"
        link(arguments, baseline_obj, gc_baseline_elf, gc_sections=True)
        link(arguments, mapped_obj, gc_mapped_elf, gc_sections=True)
        require_inertness(
            arguments,
            gc_baseline_elf,
            gc_mapped_elf,
            "section-GC policy linked map",
        )
        run([str(arguments.site_tool.resolve()), str(gc_mapped_elf)])
        if source_builtin:
            gc_source_elf = directory / "gc-source.elf"
            link(arguments, source_obj, gc_source_elf, gc_sections=True)
            require_inertness(
                arguments,
                gc_baseline_elf,
                gc_source_elf,
                "section-GC source linked map",
            )
            run([str(arguments.site_tool.resolve()), str(gc_source_elf)])

        gnu_ld_result: dict[str, object] = {"result": "not-requested"}
        if arguments.gnu_ld:
            gnu_version_output = run([
                arguments.gnu_ld, "--version"
            ]).stdout.splitlines()
            if not gnu_version_output:
                raise AssertionError("GNU ld produced no version identity")

            gnu_baseline_elf = directory / "gnu-baseline.elf"
            gnu_disabled_elf = directory / "gnu-disabled.elf"
            gnu_mapped_elf = directory / "gnu-mapped.elf"
            link(
                arguments,
                baseline_obj,
                gnu_baseline_elf,
                linker=arguments.gnu_ld,
            )
            link(
                arguments,
                disabled_obj,
                gnu_disabled_elf,
                linker=arguments.gnu_ld,
            )
            link(
                arguments,
                mapped_obj,
                gnu_mapped_elf,
                linker=arguments.gnu_ld,
            )
            require_inertness(
                arguments,
                gnu_baseline_elf,
                gnu_disabled_elf,
                "disabled GNU-ld linked map",
            )
            require_inertness(
                arguments,
                gnu_baseline_elf,
                gnu_mapped_elf,
                "policy GNU-ld linked map",
            )
            gnu_mapped_sidecar = json.loads(run([
                str(arguments.site_tool.resolve()), str(gnu_mapped_elf)
            ]).stdout)
            if len(gnu_mapped_sidecar["sites"]) != 1:
                raise AssertionError("policy GNU-ld map is incomplete")
            gnu_mapped_site = gnu_mapped_sidecar["sites"][0]
            if (
                gnu_mapped_site["site_id"] != mapped_site["site_id"]
                or gnu_mapped_site["link_va"] != mapped_site["link_va"]
            ):
                raise AssertionError(
                    "GNU ld changed the policy site's identity or address"
                )

            gnu_source_site_count = 0
            if source_builtin:
                gnu_source_elf = directory / "gnu-source.elf"
                link(
                    arguments,
                    source_obj,
                    gnu_source_elf,
                    linker=arguments.gnu_ld,
                )
                require_inertness(
                    arguments,
                    gnu_baseline_elf,
                    gnu_source_elf,
                    "source GNU-ld linked map",
                )
                gnu_source_sidecar = json.loads(run([
                    str(arguments.site_tool.resolve()), str(gnu_source_elf)
                ]).stdout)
                if len(gnu_source_sidecar["sites"]) != 1:
                    raise AssertionError("source GNU-ld map is incomplete")
                gnu_source_site = gnu_source_sidecar["sites"][0]
                if (
                    gnu_source_site["site_id"] != source_site["site_id"]
                    or gnu_source_site["link_va"] != source_site["link_va"]
                ):
                    raise AssertionError(
                        "GNU ld changed the source site's identity or address"
                    )
                gnu_source_site_count = 1

            gnu_norelax_baseline_elf = directory / "gnu-norelax-baseline.elf"
            gnu_norelax_mapped_elf = directory / "gnu-norelax-mapped.elf"
            link(
                arguments,
                norelax_baseline_obj,
                gnu_norelax_baseline_elf,
                linker=arguments.gnu_ld,
            )
            link(
                arguments,
                norelax_mapped_obj,
                gnu_norelax_mapped_elf,
                linker=arguments.gnu_ld,
            )
            require_inertness(
                arguments,
                gnu_norelax_baseline_elf,
                gnu_norelax_mapped_elf,
                "no-relax policy GNU-ld linked map",
            )
            run([
                str(arguments.site_tool.resolve()),
                str(gnu_norelax_mapped_elf),
            ])
            if source_builtin:
                gnu_norelax_source_elf = directory / "gnu-norelax-source.elf"
                link(
                    arguments,
                    norelax_source_obj,
                    gnu_norelax_source_elf,
                    linker=arguments.gnu_ld,
                )
                require_inertness(
                    arguments,
                    gnu_norelax_baseline_elf,
                    gnu_norelax_source_elf,
                    "no-relax source GNU-ld linked map",
                )
                run([
                    str(arguments.site_tool.resolve()),
                    str(gnu_norelax_source_elf),
                ])

            gnu_gc_baseline_elf = directory / "gnu-gc-baseline.elf"
            gnu_gc_mapped_elf = directory / "gnu-gc-mapped.elf"
            link(
                arguments,
                baseline_obj,
                gnu_gc_baseline_elf,
                gc_sections=True,
                linker=arguments.gnu_ld,
            )
            link(
                arguments,
                mapped_obj,
                gnu_gc_mapped_elf,
                gc_sections=True,
                linker=arguments.gnu_ld,
            )
            require_inertness(
                arguments,
                gnu_gc_baseline_elf,
                gnu_gc_mapped_elf,
                "section-GC policy GNU-ld linked map",
            )
            run([
                str(arguments.site_tool.resolve()), str(gnu_gc_mapped_elf)
            ])
            if source_builtin:
                gnu_gc_source_elf = directory / "gnu-gc-source.elf"
                link(
                    arguments,
                    source_obj,
                    gnu_gc_source_elf,
                    gc_sections=True,
                    linker=arguments.gnu_ld,
                )
                require_inertness(
                    arguments,
                    gnu_gc_baseline_elf,
                    gnu_gc_source_elf,
                    "section-GC source GNU-ld linked map",
                )
                run([
                    str(arguments.site_tool.resolve()),
                    str(gnu_gc_source_elf),
                ])

            gnu_ld_result = {
                "result": "PASS",
                "version": gnu_version_output[0],
                "policy_site_count": 1,
                "source_site_count": gnu_source_site_count,
                "disabled_plugin_identity": "PASS",
                "object_and_linked_inertness": "PASS",
                "site_id_and_address_match_lld": "PASS",
                "linker_relaxation_enabled": "PASS",
                "linker_relaxation_disabled": "PASS",
                "section_gc": "PASS",
                "thinlto": "not-supported-by-this-lane",
            }

        split_work = directory / "split-work"
        split_work.mkdir()
        split_work_obj = split_work / "probe.o"
        split_work_dwo = split_work / "probe.dwo"

        def compile_split_snapshot(
            name: str,
            *,
            plugin: bool,
            spec: pathlib.Path | None,
            source_site: bool = False,
        ) -> tuple[pathlib.Path, pathlib.Path]:
            compile_object(
                arguments,
                split_work_obj,
                plugin=plugin,
                spec=spec,
                source_site=source_site,
                split_dwarf=True,
            )
            if not split_work_dwo.is_file() or not split_work_dwo.stat().st_size:
                raise AssertionError("split-DWARF compilation emitted no DWO")
            snapshot_obj = directory / f"split-{name}.o"
            snapshot_dwo = directory / f"split-{name}.dwo"
            shutil.copyfile(split_work_obj, snapshot_obj)
            shutil.copyfile(split_work_dwo, snapshot_dwo)
            return snapshot_obj, snapshot_dwo

        split_baseline_obj, split_baseline_dwo = compile_split_snapshot(
            "baseline", plugin=False, spec=None
        )
        split_disabled_obj, split_disabled_dwo = compile_split_snapshot(
            "disabled", plugin=True, spec=None
        )
        split_mapped_obj, split_mapped_dwo = compile_split_snapshot(
            "mapped", plugin=True, spec=VALID_SPEC
        )
        if split_baseline_dwo.read_bytes() != split_disabled_dwo.read_bytes():
            raise AssertionError("disabled map plugin changed split DWARF")
        if split_baseline_dwo.read_bytes() != split_mapped_dwo.read_bytes():
            raise AssertionError("policy map changed split DWARF")
        require_inertness(
            arguments,
            split_baseline_obj,
            split_disabled_obj,
            "disabled split-DWARF object map",
        )
        require_inertness(
            arguments,
            split_baseline_obj,
            split_mapped_obj,
            "policy split-DWARF object map",
        )
        split_mapped_object_map = json.loads(run([
            str(arguments.site_tool.resolve()),
            "--validate-relocatable",
            str(split_mapped_obj),
        ]).stdout)
        if len(split_mapped_object_map["sites"]) != 1:
            raise AssertionError("policy split-DWARF object map is incomplete")
        if split_mapped_object_map["sites"][0]["site_id"] != (
            object_site["site_id"]
        ):
            raise AssertionError("policy site ID changed under split DWARF")

        split_source_site_count = 0
        split_dwo_files = [
            split_baseline_dwo,
            split_disabled_dwo,
            split_mapped_dwo,
        ]
        if source_builtin:
            split_source_obj, split_source_dwo = compile_split_snapshot(
                "source", plugin=True, spec=None, source_site=True
            )
            split_dwo_files.append(split_source_dwo)
            if split_baseline_dwo.read_bytes() != split_source_dwo.read_bytes():
                raise AssertionError("source map changed split DWARF")
            require_inertness(
                arguments,
                split_baseline_obj,
                split_source_obj,
                "source split-DWARF object map",
            )
            split_source_object_map = json.loads(run([
                str(arguments.site_tool.resolve()),
                "--validate-relocatable",
                str(split_source_obj),
            ]).stdout)
            if len(split_source_object_map["sites"]) != 1:
                raise AssertionError(
                    "source split-DWARF object map is incomplete"
                )
            if split_source_object_map["sites"][0]["site_id"] != (
                source_object_map["sites"][0]["site_id"]
            ):
                raise AssertionError("source site ID changed under split DWARF")
            split_source_site_count = 1

        llvm_dwarfdump = pathlib.Path(arguments.llvm_readobj).with_name(
            "llvm-dwarfdump"
        )
        if not llvm_dwarfdump.is_file():
            raise AssertionError(
                f"split-DWARF qualification needs {llvm_dwarfdump}"
            )
        for dwo in split_dwo_files:
            run([str(llvm_dwarfdump), "--verify", str(dwo)])

        split_baseline_elf = directory / "split-baseline.elf"
        split_disabled_elf = directory / "split-disabled.elf"
        split_mapped_elf = directory / "split-mapped.elf"
        link(arguments, split_baseline_obj, split_baseline_elf)
        link(arguments, split_disabled_obj, split_disabled_elf)
        link(arguments, split_mapped_obj, split_mapped_elf)
        require_inertness(
            arguments,
            split_baseline_elf,
            split_disabled_elf,
            "disabled split-DWARF linked map",
        )
        require_inertness(
            arguments,
            split_baseline_elf,
            split_mapped_elf,
            "policy split-DWARF linked map",
        )
        split_mapped_sidecar = json.loads(run([
            str(arguments.site_tool.resolve()), str(split_mapped_elf)
        ]).stdout)
        if len(split_mapped_sidecar["sites"]) != 1:
            raise AssertionError("policy split-DWARF linked map is incomplete")
        if split_mapped_sidecar["sites"][0]["site_id"] != (
            mapped_site["site_id"]
        ):
            raise AssertionError("linked policy site ID changed under split DWARF")
        if source_builtin:
            split_source_elf = directory / "split-source.elf"
            link(arguments, split_source_obj, split_source_elf)
            require_inertness(
                arguments,
                split_baseline_elf,
                split_source_elf,
                "source split-DWARF linked map",
            )
            split_source_sidecar = json.loads(run([
                str(arguments.site_tool.resolve()), str(split_source_elf)
            ]).stdout)
            if len(split_source_sidecar["sites"]) != 1:
                raise AssertionError(
                    "source split-DWARF linked map is incomplete"
                )
            if split_source_sidecar["sites"][0]["site_id"] != (
                source_site["site_id"]
            ):
                raise AssertionError(
                    "linked source site ID changed under split DWARF"
                )

        thin_baseline_obj = directory / "thin-baseline.o"
        thin_disabled_obj = directory / "thin-disabled.o"
        thin_mapped_obj = directory / "thin-mapped.o"
        compile_object(
            arguments,
            thin_baseline_obj,
            plugin=False,
            spec=None,
            thin_lto=True,
        )
        compile_object(
            arguments,
            thin_disabled_obj,
            plugin=True,
            spec=None,
            thin_lto=True,
        )
        compile_object(
            arguments,
            thin_mapped_obj,
            plugin=True,
            spec=VALID_SPEC,
            thin_lto=True,
        )
        thin_baseline_elf = directory / "thin-baseline.elf"
        thin_disabled_elf = directory / "thin-disabled.elf"
        thin_mapped_elf = directory / "thin-mapped.elf"
        link(arguments, thin_baseline_obj, thin_baseline_elf)
        link(arguments, thin_disabled_obj, thin_disabled_elf)
        link(arguments, thin_mapped_obj, thin_mapped_elf)
        require_inertness(
            arguments,
            thin_baseline_elf,
            thin_disabled_elf,
            "disabled ThinLTO linked map",
        )
        require_inertness(
            arguments,
            thin_baseline_elf,
            thin_mapped_elf,
            "policy ThinLTO linked map",
        )
        thin_mapped_sidecar = json.loads(run([
            str(arguments.site_tool.resolve()), str(thin_mapped_elf)
        ]).stdout)
        if len(thin_mapped_sidecar["sites"]) != 1:
            raise AssertionError("policy ThinLTO map is incomplete")
        thin_mapped_site = thin_mapped_sidecar["sites"][0]
        if (
            thin_mapped_site["kind"] != 39
            or thin_mapped_site["symbol"] != "irq_map_probe"
        ):
            raise AssertionError(
                f"policy ThinLTO site is malformed: {thin_mapped_site!r}"
            )
        if thin_mapped_site["site_id"] != mapped_site["site_id"]:
            raise AssertionError("policy site ID changed under ThinLTO")

        thin_source_site_count = 0
        if source_builtin:
            thin_source_obj = directory / "thin-source.o"
            thin_source_elf = directory / "thin-source.elf"
            compile_object(
                arguments,
                thin_source_obj,
                plugin=True,
                spec=None,
                source_site=True,
                thin_lto=True,
            )
            link(arguments, thin_source_obj, thin_source_elf)
            require_inertness(
                arguments,
                thin_baseline_elf,
                thin_source_elf,
                "source ThinLTO linked map",
            )
            thin_source_sidecar = json.loads(run([
                str(arguments.site_tool.resolve()), str(thin_source_elf)
            ]).stdout)
            if len(thin_source_sidecar["sites"]) != 1:
                raise AssertionError("source ThinLTO map is incomplete")
            thin_source_site = thin_source_sidecar["sites"][0]
            if (
                thin_source_site["kind"] != 39
                or thin_source_site["symbol"] != "irq_map_probe"
            ):
                raise AssertionError(
                    f"source ThinLTO site is malformed: {thin_source_site!r}"
                )
            if thin_source_site["site_id"] != source_site["site_id"]:
                raise AssertionError("source site ID changed under ThinLTO")
            if thin_source_site["link_va"] != thin_mapped_site["link_va"]:
                raise AssertionError(
                    "source and policy ThinLTO sites did not anchor the same "
                    "store"
                )
            thin_source_site_count = 1

        thin_gc_baseline_elf = directory / "thin-gc-baseline.elf"
        thin_gc_mapped_elf = directory / "thin-gc-mapped.elf"
        link(
            arguments,
            thin_baseline_obj,
            thin_gc_baseline_elf,
            gc_sections=True,
        )
        link(
            arguments,
            thin_mapped_obj,
            thin_gc_mapped_elf,
            gc_sections=True,
        )
        require_inertness(
            arguments,
            thin_gc_baseline_elf,
            thin_gc_mapped_elf,
            "section-GC policy ThinLTO linked map",
        )
        run([
            str(arguments.site_tool.resolve()), str(thin_gc_mapped_elf)
        ])
        if source_builtin:
            thin_gc_source_elf = directory / "thin-gc-source.elf"
            link(
                arguments,
                thin_source_obj,
                thin_gc_source_elf,
                gc_sections=True,
            )
            require_inertness(
                arguments,
                thin_gc_baseline_elf,
                thin_gc_source_elf,
                "section-GC source ThinLTO linked map",
            )
            run([
                str(arguments.site_tool.resolve()), str(thin_gc_source_elf)
            ])

        cross_caller_obj = directory / "cross-caller.o"
        cross_multi_caller_obj = directory / "cross-multi-caller.o"
        cross_baseline_obj = directory / "cross-baseline.o"
        cross_disabled_obj = directory / "cross-disabled.o"
        cross_mapped_obj = directory / "cross-mapped.o"
        compile_object(
            arguments,
            cross_caller_obj,
            plugin=False,
            spec=None,
            thin_lto=True,
            source=LTO_CALLER_SOURCE,
        )
        compile_object(
            arguments,
            cross_multi_caller_obj,
            plugin=False,
            spec=None,
            thin_lto=True,
            source=LTO_MULTI_CALLER_SOURCE,
        )
        compile_object(
            arguments,
            cross_baseline_obj,
            plugin=False,
            spec=None,
            thin_lto=True,
            source=LTO_SITE_SOURCE,
        )
        compile_object(
            arguments,
            cross_disabled_obj,
            plugin=True,
            spec=None,
            thin_lto=True,
            source=LTO_SITE_SOURCE,
        )
        compile_object(
            arguments,
            cross_mapped_obj,
            plugin=True,
            spec=CROSS_TU_SPEC,
            thin_lto=True,
            source=LTO_SITE_SOURCE,
        )

        cross_baseline_elf = directory / "cross-baseline.elf"
        cross_disabled_elf = directory / "cross-disabled.elf"
        cross_mapped_elf = directory / "cross-mapped.elf"
        cross_objects = [cross_caller_obj, cross_baseline_obj]
        link(
            arguments,
            cross_objects,
            cross_baseline_elf,
            gc_sections=True,
            entry="lto_irq_entry",
        )
        link(
            arguments,
            [cross_caller_obj, cross_disabled_obj],
            cross_disabled_elf,
            gc_sections=True,
            entry="lto_irq_entry",
        )
        link(
            arguments,
            [cross_caller_obj, cross_mapped_obj],
            cross_mapped_elf,
            gc_sections=True,
            entry="lto_irq_entry",
        )
        require_inertness(
            arguments,
            cross_baseline_elf,
            cross_disabled_elf,
            "disabled cross-TU ThinLTO linked map",
        )
        require_inertness(
            arguments,
            cross_baseline_elf,
            cross_mapped_elf,
            "policy cross-TU ThinLTO linked map",
        )
        cross_mapped_sidecar = json.loads(run([
            str(arguments.site_tool.resolve()), str(cross_mapped_elf)
        ]).stdout)
        if len(cross_mapped_sidecar["sites"]) != 1:
            raise AssertionError("policy cross-TU ThinLTO map is incomplete")
        cross_mapped_site = cross_mapped_sidecar["sites"][0]
        if (
            cross_mapped_site["kind"] != 39
            or cross_mapped_site["symbol"] != "lto_irq_entry"
        ):
            raise AssertionError(
                "policy cross-TU site was not imported into the live caller: "
                f"{cross_mapped_site!r}"
            )

        direct_mapped_obj = directory / "cross-direct-mapped.o"
        compile_object(
            arguments,
            direct_mapped_obj,
            plugin=True,
            spec=CROSS_TU_SPEC,
            source=LTO_SITE_SOURCE,
        )
        direct_mapped_map = json.loads(run([
            str(arguments.site_tool.resolve()),
            "--validate-relocatable",
            str(direct_mapped_obj),
        ]).stdout)
        if direct_mapped_map["sites"][0]["site_id"] != (
            cross_mapped_site["site_id"]
        ):
            raise AssertionError("policy site ID changed across ThinLTO import")

        cross_source_site_count = 0
        if source_builtin:
            cross_source_obj = directory / "cross-source.o"
            cross_source_elf = directory / "cross-source.elf"
            compile_object(
                arguments,
                cross_source_obj,
                plugin=True,
                spec=None,
                source_site=True,
                thin_lto=True,
                source=LTO_SITE_SOURCE,
            )
            link(
                arguments,
                [cross_caller_obj, cross_source_obj],
                cross_source_elf,
                gc_sections=True,
                entry="lto_irq_entry",
            )
            require_inertness(
                arguments,
                cross_baseline_elf,
                cross_source_elf,
                "source cross-TU ThinLTO linked map",
            )
            cross_source_sidecar = json.loads(run([
                str(arguments.site_tool.resolve()), str(cross_source_elf)
            ]).stdout)
            if len(cross_source_sidecar["sites"]) != 1:
                raise AssertionError(
                    "source cross-TU ThinLTO map is incomplete"
                )
            cross_source_site = cross_source_sidecar["sites"][0]
            if (
                cross_source_site["kind"] != 39
                or cross_source_site["symbol"] != "lto_irq_entry"
            ):
                raise AssertionError(
                    "source cross-TU site was not imported into the live "
                    f"caller: {cross_source_site!r}"
                )
            direct_source_obj = directory / "cross-direct-source.o"
            compile_object(
                arguments,
                direct_source_obj,
                plugin=True,
                spec=None,
                source_site=True,
                source=LTO_SITE_SOURCE,
            )
            direct_source_map = json.loads(run([
                str(arguments.site_tool.resolve()),
                "--validate-relocatable",
                str(direct_source_obj),
            ]).stdout)
            if direct_source_map["sites"][0]["site_id"] != (
                cross_source_site["site_id"]
            ):
                raise AssertionError(
                    "source site ID changed across ThinLTO import"
                )
            if cross_source_site["link_va"] != cross_mapped_site["link_va"]:
                raise AssertionError(
                    "source and policy cross-TU sites did not anchor the same "
                    "imported store"
                )
            cross_source_site_count = 1

        def require_map_rejection(
            image: pathlib.Path, description: str, expected_error: str
        ) -> None:
            rejected = run(
                [str(arguments.site_tool.resolve()), str(image)], check=False
            )
            if rejected.returncode == 0:
                raise AssertionError(
                    f"{description} unexpectedly passed map validation"
                )
            if expected_error not in rejected.stderr:
                raise AssertionError(
                    f"unexpected {description} error: {rejected.stderr!r}"
                )

        cross_retained_baseline_elf = directory / "cross-retained-baseline.elf"
        cross_retained_mapped_elf = directory / "cross-retained-mapped.elf"
        link(
            arguments,
            cross_objects,
            cross_retained_baseline_elf,
            entry="lto_irq_entry",
        )
        link(
            arguments,
            [cross_caller_obj, cross_mapped_obj],
            cross_retained_mapped_elf,
            entry="lto_irq_entry",
        )
        require_inertness(
            arguments,
            cross_retained_baseline_elf,
            cross_retained_mapped_elf,
            "retained-copy policy cross-TU ThinLTO linked map",
        )
        require_map_rejection(
            cross_retained_mapped_elf,
            "retained-copy policy map",
            "duplicate site identifier",
        )

        cross_multi_baseline_elf = directory / "cross-multi-baseline.elf"
        cross_multi_mapped_elf = directory / "cross-multi-mapped.elf"
        link(
            arguments,
            [cross_multi_caller_obj, cross_baseline_obj],
            cross_multi_baseline_elf,
            gc_sections=True,
            entry="lto_multi_irq_entry",
        )
        link(
            arguments,
            [cross_multi_caller_obj, cross_mapped_obj],
            cross_multi_mapped_elf,
            gc_sections=True,
            entry="lto_multi_irq_entry",
        )
        require_inertness(
            arguments,
            cross_multi_baseline_elf,
            cross_multi_mapped_elf,
            "multi-copy policy cross-TU ThinLTO linked map",
        )
        require_map_rejection(
            cross_multi_mapped_elf,
            "multi-copy policy map",
            "site section ends with a partial record",
        )
        if source_builtin:
            cross_retained_source_elf = directory / "cross-retained-source.elf"
            cross_multi_source_elf = directory / "cross-multi-source.elf"
            link(
                arguments,
                [cross_caller_obj, cross_source_obj],
                cross_retained_source_elf,
                entry="lto_irq_entry",
            )
            link(
                arguments,
                [cross_multi_caller_obj, cross_source_obj],
                cross_multi_source_elf,
                gc_sections=True,
                entry="lto_multi_irq_entry",
            )
            require_inertness(
                arguments,
                cross_retained_baseline_elf,
                cross_retained_source_elf,
                "retained-copy source cross-TU ThinLTO linked map",
            )
            require_inertness(
                arguments,
                cross_multi_baseline_elf,
                cross_multi_source_elf,
                "multi-copy source cross-TU ThinLTO linked map",
            )
            require_map_rejection(
                cross_retained_source_elf,
                "retained-copy source map",
                "duplicate site identifier",
            )
            require_map_rejection(
                cross_multi_source_elf,
                "multi-copy source map",
                "site section ends with a partial record",
            )

        gap_compile = compile_object(
            arguments, gap_obj, plugin=True, spec=GAP_SPEC
        )
        gap_elf = directory / "gap.elf"
        if arguments.selectiondag_expect == "loss":
            if "loosing !pcsections" not in gap_compile.stderr:
                raise AssertionError(
                    "negative fixture did not exercise metadata loss"
                )
            link(arguments, gap_obj, gap_elf)
            rejected = run(
                [str(arguments.site_tool.resolve()), str(gap_elf)], check=False
            )
            if rejected.returncode == 0:
                raise AssertionError("site tool accepted silently dropped C sites")
            if "C carrier/expectation mismatch" not in rejected.stderr:
                raise AssertionError(
                    f"unexpected coverage error: {rejected.stderr!r}"
                )
            selectiondag_site_count = 1
            selectiondag_text_identity = "coverage-rejected"
        else:
            if "loosing !pcsections" in gap_compile.stderr:
                raise AssertionError(
                    f"patched SelectionDAG lost requested sites: "
                    f"{gap_compile.stderr}"
                )
            gap_obj_text = dump_section(
                arguments, gap_obj, ".text", directory / "gap-o.text"
            )
            if baseline_obj_text != gap_obj_text:
                raise AssertionError("patched SelectionDAG map changed object .text")
            gap_object_map = json.loads(run([
                str(arguments.site_tool.resolve()),
                "--validate-relocatable",
                str(gap_obj),
            ]).stdout)
            if {entry["kind"] for entry in gap_object_map["sites"]} != {
                4, 5, 37, 39,
            }:
                raise AssertionError(
                    "patched SelectionDAG object has unexpected site kinds"
                )
            if len(gap_object_map["sites"]) != 4:
                raise AssertionError(
                    "patched SelectionDAG object did not preserve four sites"
                )

            link(arguments, gap_obj, gap_elf)
            gap_elf_text = dump_section(
                arguments, gap_elf, ".text", directory / "gap-e.text"
            )
            if baseline_elf_text != gap_elf_text:
                raise AssertionError("patched SelectionDAG map changed linked .text")
            gap_sidecar = json.loads(run([
                str(arguments.site_tool.resolve()), str(gap_elf)
            ]).stdout)
            if {entry["kind"] for entry in gap_sidecar["sites"]} != {
                4, 5, 37, 39,
            }:
                raise AssertionError(
                    "patched SelectionDAG sidecar has unexpected site kinds"
                )
            selectiondag_site_count = 4
            selectiondag_text_identity = "PASS"

        compile_object(
            arguments,
            gisel_baseline_obj,
            plugin=False,
            spec=None,
            global_isel=True,
        )
        gisel_compile = compile_object(
            arguments,
            gisel_mapped_obj,
            plugin=True,
            spec=GAP_SPEC,
            global_isel=True,
        )
        if (
            arguments.global_isel_expect == "complete"
            and "loosing !pcsections" in gisel_compile.stderr
        ):
            raise AssertionError(
                f"GlobalISel lost requested sites: {gisel_compile.stderr}"
            )
        gisel_baseline_obj_text = dump_section(
            arguments,
            gisel_baseline_obj,
            ".text",
            directory / "gisel-baseline-o.text",
        )
        gisel_mapped_obj_text = dump_section(
            arguments,
            gisel_mapped_obj,
            ".text",
            directory / "gisel-mapped-o.text",
        )
        if gisel_baseline_obj_text != gisel_mapped_obj_text:
            raise AssertionError("GlobalISel C map changed object .text")
        gisel_object_command = [
            str(arguments.site_tool.resolve()),
            "--validate-relocatable",
            str(gisel_mapped_obj),
        ]
        if arguments.global_isel_expect == "complete":
            gisel_object_map = json.loads(run(gisel_object_command).stdout)
            global_isel_site_kinds = sorted(
                entry["kind"] for entry in gisel_object_map["sites"]
            )
            if global_isel_site_kinds != [4, 5, 37, 39]:
                raise AssertionError(
                    "GlobalISel object did not preserve the four expected sites"
                )
            global_isel_site_count = 4
        else:
            rejected = run(gisel_object_command, check=False)
            if rejected.returncode == 0:
                raise AssertionError(
                    "GlobalISel unexpectedly preserved every requested site"
                )
            if "C carrier/expectation mismatch" not in rejected.stderr:
                raise AssertionError(
                    f"unexpected GlobalISel coverage error: {rejected.stderr!r}"
                )
            carrier = dump_section(
                arguments,
                gisel_mapped_obj,
                ".riscv.linux_irq_c_sites",
                directory / "gisel-sites.bin",
            )
            if len(carrier) % 32:
                raise AssertionError("GlobalISel emitted a partial site record")
            global_isel_site_count = len(carrier) // 32
            global_isel_site_kinds = sorted(
                int.from_bytes(carrier[offset + 10:offset + 12], "little")
                for offset in range(0, len(carrier), 32)
            )
            if global_isel_site_kinds != [4, 5, 37]:
                raise AssertionError(
                    "GlobalISel did not drop only the publication-store site"
                )

        gisel_baseline_elf = directory / "gisel-baseline.elf"
        gisel_mapped_elf = directory / "gisel-mapped.elf"
        link(arguments, gisel_baseline_obj, gisel_baseline_elf)
        link(arguments, gisel_mapped_obj, gisel_mapped_elf)
        gisel_baseline_elf_text = dump_section(
            arguments,
            gisel_baseline_elf,
            ".text",
            directory / "gisel-baseline-e.text",
        )
        gisel_mapped_elf_text = dump_section(
            arguments,
            gisel_mapped_elf,
            ".text",
            directory / "gisel-mapped-e.text",
        )
        if gisel_baseline_elf_text != gisel_mapped_elf_text:
            raise AssertionError("GlobalISel C map changed linked .text")
        gisel_sidecar_command = [
            str(arguments.site_tool.resolve()), str(gisel_mapped_elf)
        ]
        if arguments.global_isel_expect == "complete":
            gisel_sidecar = json.loads(run(gisel_sidecar_command).stdout)
            if {entry["kind"] for entry in gisel_sidecar["sites"]} != {
                4, 5, 37, 39,
            }:
                raise AssertionError(
                    "GlobalISel sidecar has unexpected site kinds"
                )
            global_isel_coverage = "complete"
        else:
            rejected = run(gisel_sidecar_command, check=False)
            if rejected.returncode == 0:
                raise AssertionError(
                    "linked GlobalISel map unexpectedly passed its coverage gate"
                )
            if "C carrier/expectation mismatch" not in rejected.stderr:
                raise AssertionError(
                    f"unexpected linked GlobalISel error: {rejected.stderr!r}"
                )
            global_isel_coverage = "coverage-rejected"

        object_fingerprint = elf_inertness_fingerprint(arguments, baseline_obj)
        linked_fingerprint = elf_inertness_fingerprint(arguments, baseline_elf)
        print(json.dumps({
            "result": "PASS",
            "target": "riscv64-unknown-linux-gnu",
            "mode": "text-inert-pcsections",
            "text_bytes": len(mapped_elf_text),
            "site_count": 1,
            "source_builtin_expectation": arguments.source_builtin_expect,
            "source_builtin_site_count": 1 if source_builtin else 0,
            "source_builtin_text_identity": (
                "PASS" if source_builtin else "unavailable"
            ),
            "source_builtin_anchor_matches_policy": (
                True if source_builtin else None
            ),
            "source_builtin_optimization_levels": source_optimization_levels,
            "source_builtin_prefix_map_identity": (
                "PASS" if source_builtin else "unavailable"
            ),
            "source_builtin_missing_line_tables": (
                "coverage-rejected" if source_builtin else "unavailable"
            ),
            "elf_inertness": {
                "allocated_sections": {
                    "result": "PASS",
                    "object_count": len(
                        object_fingerprint["allocated_sections"]
                    ),
                    "linked_count": len(
                        linked_fingerprint["allocated_sections"]
                    ),
                },
                "executable_sections": {
                    "result": "PASS",
                    "object_count": len(
                        object_fingerprint["executable_sections"]
                    ),
                    "linked_count": len(
                        linked_fingerprint["executable_sections"]
                    ),
                },
                "meaningful_symbols": {
                    "result": "PASS",
                    "object_count": len(object_fingerprint["symbols"]),
                    "linked_count": len(linked_fingerprint["symbols"]),
                },
                "code_relocations": {
                    "result": "PASS",
                    "object_count": len(
                        object_fingerprint["code_relocations"]
                    ),
                    "linked_count": len(
                        linked_fingerprint["code_relocations"]
                    ),
                },
                "unwind_sections_and_relocations": {
                    "result": "PASS",
                    "object_sections": len(
                        object_fingerprint["unwind_sections"]
                    ),
                    "linked_sections": len(
                        linked_fingerprint["unwind_sections"]
                    ),
                    "object_relocations": len(
                        object_fingerprint["unwind_relocations"]
                    ),
                    "linked_relocations": len(
                        linked_fingerprint["unwind_relocations"]
                    ),
                },
                "linker_relaxation_enabled": "PASS",
                "linker_relaxation_disabled": "PASS",
                "section_gc": "PASS",
            },
            "thinlto": {
                "result": "PASS",
                "policy_site_count": 1,
                "source_site_count": thin_source_site_count,
                "disabled_plugin_identity": "PASS",
                "all_executable_sections_identity": "PASS",
                "allocated_sections_symbols_relocations_unwind": "PASS",
                "site_id_stability": "PASS",
                "section_gc": "PASS",
            },
            "cross_tu_thinlto": {
                "result": "PASS_WITH_EXPLICIT_COPY_LIMIT",
                "final_symbol": "lto_irq_entry",
                "policy_site_count": 1,
                "source_site_count": cross_source_site_count,
                "import_and_inline": "PASS",
                "disabled_plugin_identity": "PASS",
                "object_and_linked_inertness": "PASS",
                "site_id_stability": "PASS",
                "retained_out_of_line_copy": "duplicate-rejected",
                "multiple_live_inline_copies": "partial-record-rejected",
            },
            "gnu_ld": gnu_ld_result,
            "split_dwarf": {
                "result": "PASS",
                "policy_site_count": 1,
                "source_site_count": split_source_site_count,
                "disabled_plugin_identity": "PASS",
                "dwo_byte_identity": "PASS",
                "dwo_verification": "PASS",
                "object_and_linked_inertness": "PASS",
                "site_id_stability": "PASS",
            },
            "object_relocations": "PASS",
            "selectiondag_expectation": arguments.selectiondag_expect,
            "selectiondag_site_count": selectiondag_site_count,
            "selectiondag_text_identity": selectiondag_text_identity,
            "selectiondag_coverage_gate": "PASS",
            "global_isel_expectation": arguments.global_isel_expect,
            "global_isel_site_count": global_isel_site_count,
            "global_isel_site_kinds": global_isel_site_kinds,
            "global_isel_coverage": global_isel_coverage,
            "global_isel_text_identity": "PASS",
            "trigger_phase": sidecar["trigger_phase"],
        }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
