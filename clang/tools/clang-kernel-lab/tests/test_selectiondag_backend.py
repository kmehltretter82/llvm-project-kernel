#!/usr/bin/env python3
"""Qualify patched RISC-V SelectionDAG PC-section propagation end to end."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import subprocess
import tempfile


HERE = pathlib.Path(__file__).resolve().parent
TOOL = HERE.parent
SOURCE = HERE / "map-probe.c"
LINKER_SCRIPT = HERE / "map-link.ld"
SPEC = TOOL / "examples" / "riscv-map-coverage-gap-v1.json"


def run(command: list[str], *, environment: dict[str, str] | None = None,
        check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    if check and result.returncode:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(command)}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def compile_ir(arguments: argparse.Namespace, output: pathlib.Path,
               *, mapped: bool) -> None:
    environment = os.environ.copy()
    if mapped:
        environment["CLANG_KERNEL_LAB_MAP_SPEC"] = str(SPEC)
    else:
        environment.pop("CLANG_KERNEL_LAB_MAP_SPEC", None)
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
    if mapped:
        command.append(f"-fpass-plugin={arguments.plugin.resolve()}")
    command.extend(["-S", "-emit-llvm", str(SOURCE), "-o", str(output)])
    run(command, environment=environment)


def compile_object(arguments: argparse.Namespace, source: pathlib.Path,
                   output: pathlib.Path) -> None:
    result = run([
        str(arguments.llc.resolve()),
        "-filetype=obj",
        "-O2",
        "-mtriple=riscv64-unknown-linux-gnu",
        "-mattr=+m,+a",
        "-code-model=medium",
        str(source),
        "-o", str(output),
    ])
    if "loosing !pcsections" in result.stderr:
        raise AssertionError(f"SelectionDAG lost a requested site: {result.stderr}")


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


def dump_text(arguments: argparse.Namespace, binary: pathlib.Path,
              output: pathlib.Path) -> bytes:
    run([
        arguments.llvm_objcopy,
        f"--dump-section=.text={output}",
        str(binary),
    ])
    return output.read_bytes()


def disassembly(arguments: argparse.Namespace,
                binary: pathlib.Path) -> dict[int, str]:
    output = run([
        arguments.llvm_objdump,
        "-d",
        "--no-show-raw-insn",
        str(binary),
    ]).stdout
    instructions: dict[int, str] = {}
    pattern = re.compile(r"^\s*([0-9a-fA-F]+):\s+([a-zA-Z0-9_.]+)", re.MULTILINE)
    for match in pattern.finditer(output):
        instructions[int(match.group(1), 16)] = match.group(2)
    return instructions


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clang", required=True)
    parser.add_argument("--llc", required=True, type=pathlib.Path)
    parser.add_argument("--ld-lld", required=True)
    parser.add_argument("--llvm-objcopy", required=True)
    parser.add_argument("--llvm-objdump", required=True)
    parser.add_argument("--plugin", required=True, type=pathlib.Path)
    parser.add_argument("--site-tool", required=True, type=pathlib.Path)
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    with tempfile.TemporaryDirectory(
        prefix="clang-kernel-lab-selectiondag-"
    ) as temporary:
        directory = pathlib.Path(temporary)
        baseline_ir = directory / "baseline.ll"
        mapped_ir = directory / "mapped.ll"
        baseline_obj = directory / "baseline.o"
        mapped_obj = directory / "mapped.o"
        baseline_elf = directory / "baseline.elf"
        mapped_elf = directory / "mapped.elf"

        compile_ir(arguments, baseline_ir, mapped=False)
        compile_ir(arguments, mapped_ir, mapped=True)
        compile_object(arguments, baseline_ir, baseline_obj)
        compile_object(arguments, mapped_ir, mapped_obj)

        baseline_object_text = dump_text(
            arguments, baseline_obj, directory / "baseline-object.text"
        )
        mapped_object_text = dump_text(
            arguments, mapped_obj, directory / "mapped-object.text"
        )
        if baseline_object_text != mapped_object_text:
            raise AssertionError("patched SelectionDAG map changed object .text")

        object_map = json.loads(run([
            str(arguments.site_tool.resolve()),
            "--validate-relocatable",
            str(mapped_obj),
        ]).stdout)
        if object_map["artifact_kind"] != "relocatable-object":
            raise AssertionError("site tool returned the wrong artifact kind")
        if {site["kind"] for site in object_map["sites"]} != {4, 5, 37, 39}:
            raise AssertionError("patched SelectionDAG object lacks expected sites")
        if len(object_map["sites"]) != 4:
            raise AssertionError("patched SelectionDAG object has duplicate sites")
        for site in object_map["sites"]:
            if site["relocation_type"] != "R_RISCV_ADD64+R_RISCV_SUB64":
                raise AssertionError("C site has the wrong relocation pair")

        link(arguments, baseline_obj, baseline_elf)
        link(arguments, mapped_obj, mapped_elf)
        baseline_linked_text = dump_text(
            arguments, baseline_elf, directory / "baseline-linked.text"
        )
        mapped_linked_text = dump_text(
            arguments, mapped_elf, directory / "mapped-linked.text"
        )
        if baseline_linked_text != mapped_linked_text:
            raise AssertionError("patched SelectionDAG map changed linked .text")

        sidecar = json.loads(run([
            str(arguments.site_tool.resolve()), str(mapped_elf)
        ]).stdout)
        if len(sidecar["sites"]) != 4:
            raise AssertionError("linked sidecar does not contain four sites")
        instructions = disassembly(arguments, mapped_elf)
        expected_mnemonics = {4: "jal", 5: "ret", 37: "jal", 39: "sw"}
        for site in sidecar["sites"]:
            address = int(site["link_va"], 0)
            actual = instructions.get(address)
            expected = expected_mnemonics[site["kind"]]
            if actual != expected:
                raise AssertionError(
                    f"site kind {site['kind']} resolves to {actual!r}, "
                    f"expected {expected!r} at {address:#x}"
                )

        print(json.dumps({
            "result": "PASS",
            "target": "riscv64-unknown-linux-gnu",
            "backend": "SelectionDAG-pcsections-patched",
            "site_count": 4,
            "site_kinds": [4, 5, 37, 39],
            "object_text_identity": "PASS",
            "linked_text_identity": "PASS",
            "final_pc_mnemonics": "PASS",
            "text_bytes": len(mapped_linked_text),
            "trigger_phase": sidecar["trigger_phase"],
        }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
