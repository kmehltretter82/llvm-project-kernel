#!/usr/bin/env python3
"""Prove the late C map pass is text-inert and coverage-checked."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import tempfile


HERE = pathlib.Path(__file__).resolve().parent
TOOL = HERE.parent
SOURCE = HERE / "map-probe.c"
LINKER_SCRIPT = HERE / "map-link.ld"
VALID_SPEC = TOOL / "examples" / "riscv-map-v1.json"
GAP_SPEC = TOOL / "examples" / "riscv-map-coverage-gap-v1.json"


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
        "-O2",
        "-gline-tables-only",
        "-ffreestanding",
        "-fno-addrsig",
    ]
    if global_isel:
        command.extend(["-fglobal-isel", "-Wno-global-isel"])
    if plugin:
        command.append(f"-fpass-plugin={arguments.plugin.resolve()}")
    command.extend(["-c", str(SOURCE), "-o", str(output)])
    return run(command, environment=environment)


def link(arguments: argparse.Namespace, obj: pathlib.Path,
         output: pathlib.Path) -> None:
    run([
        arguments.ld_lld,
        "-m", "elf64lriscv",
        "-e", "irq_map_probe",
        "-T", str(LINKER_SCRIPT),
        str(obj),
        "-o", str(output),
    ])


def dump_section(arguments: argparse.Namespace, binary: pathlib.Path,
                 section: str, output: pathlib.Path) -> bytes:
    run([
        arguments.llvm_objcopy,
        f"--dump-section={section}={output}",
        str(binary),
    ])
    return output.read_bytes()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clang", required=True)
    parser.add_argument("--ld-lld", required=True)
    parser.add_argument("--llvm-objcopy", required=True)
    parser.add_argument("--plugin", required=True, type=pathlib.Path)
    parser.add_argument("--site-tool", required=True, type=pathlib.Path)
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    with tempfile.TemporaryDirectory(prefix="clang-kernel-lab-map-") as temp:
        directory = pathlib.Path(temp)
        baseline_obj = directory / "baseline.o"
        disabled_obj = directory / "disabled.o"
        mapped_obj = directory / "mapped.o"
        gap_obj = directory / "gap.o"
        gisel_baseline_obj = directory / "gisel-baseline.o"
        gisel_mapped_obj = directory / "gisel-mapped.o"

        compile_object(arguments, baseline_obj, plugin=False, spec=None)
        compile_object(arguments, disabled_obj, plugin=True, spec=None)
        mapped_compile = compile_object(
            arguments, mapped_obj, plugin=True, spec=VALID_SPEC
        )
        if "loosing !pcsections" in mapped_compile.stderr:
            raise AssertionError(
                f"qualified map unexpectedly lost metadata: {mapped_compile.stderr}"
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

        baseline_elf = directory / "baseline.elf"
        disabled_elf = directory / "disabled.elf"
        mapped_elf = directory / "mapped.elf"
        link(arguments, baseline_obj, baseline_elf)
        link(arguments, disabled_obj, disabled_elf)
        link(arguments, mapped_obj, mapped_elf)
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

        gap_compile = compile_object(
            arguments, gap_obj, plugin=True, spec=GAP_SPEC
        )
        if "loosing !pcsections" not in gap_compile.stderr:
            raise AssertionError("negative fixture did not exercise metadata loss")
        gap_elf = directory / "gap.elf"
        link(arguments, gap_obj, gap_elf)
        rejected = run(
            [str(arguments.site_tool.resolve()), str(gap_elf)], check=False
        )
        if rejected.returncode == 0:
            raise AssertionError("site tool accepted silently dropped C sites")
        if "C carrier/expectation mismatch" not in rejected.stderr:
            raise AssertionError(f"unexpected coverage error: {rejected.stderr!r}")

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
        if "loosing !pcsections" in gisel_compile.stderr:
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
        gisel_object_map = json.loads(run([
            str(arguments.site_tool.resolve()),
            "--validate-relocatable",
            str(gisel_mapped_obj),
        ]).stdout)
        if len(gisel_object_map["sites"]) != 4:
            raise AssertionError("GlobalISel object did not preserve four sites")

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
        gisel_sidecar = json.loads(run([
            str(arguments.site_tool.resolve()), str(gisel_mapped_elf)
        ]).stdout)
        if {entry["kind"] for entry in gisel_sidecar["sites"]} != {
            4, 5, 37, 39,
        }:
            raise AssertionError("GlobalISel sidecar has unexpected site kinds")

        print(json.dumps({
            "result": "PASS",
            "target": "riscv64-unknown-linux-gnu",
            "mode": "text-inert-pcsections",
            "text_bytes": len(mapped_elf_text),
            "site_count": 1,
            "object_relocations": "PASS",
            "lost_site_negative": "PASS",
            "global_isel_site_count": 4,
            "global_isel_text_identity": "PASS",
            "trigger_phase": sidecar["trigger_phase"],
        }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
