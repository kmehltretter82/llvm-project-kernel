#!/usr/bin/env python3
"""Build two tiny RV64 ELFs and prove map mode leaves .text unchanged."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import irq_site_format as site


HERE = pathlib.Path(__file__).resolve().parent
INPUTS = HERE / "Inputs" / "RISCVSiteMap"
INCLUDE = HERE.parent / "riscv"
CLANG_INCLUDE = HERE.parents[2] / "include"


def run(command: list[str]) -> None:
    subprocess.run(command, check=True)


def run_captured(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True)


def dump_section(objcopy: str, binary: pathlib.Path, section: str,
                 output: pathlib.Path) -> bytes:
    run([objcopy, f"--dump-section={section}={output}", str(binary)])
    return output.read_bytes()


def assemble(arguments: argparse.Namespace, source: pathlib.Path,
             stem: str, directory: pathlib.Path) -> pathlib.Path:
    obj = directory / f"{stem}.o"
    run([
        arguments.clang,
        "--target=riscv64-unknown-elf",
        "-march=rv64ima",
        "-mabi=lp64",
        "-x", "assembler-with-cpp",
        "-I", str(INCLUDE),
        "-I", str(CLANG_INCLUDE),
        "-c", str(source),
        "-o", str(obj),
    ])
    return obj


def build(arguments: argparse.Namespace, source: pathlib.Path,
          stem: str, directory: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    obj = assemble(arguments, source, stem, directory)
    elf = directory / f"{stem}.elf"
    run([
        arguments.ld_lld,
        "-m", "elf64lriscv",
        "-T", str(INPUTS / "link.ld"),
        str(obj),
        "-o", str(elf),
    ])
    return obj, elf


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--clang", default=os.environ.get("CLANG", "clang"))
    result.add_argument("--ld-lld", default=os.environ.get("LD_LLD", "ld.lld"))
    result.add_argument(
        "--llvm-objcopy", default=os.environ.get("LLVM_OBJCOPY", "llvm-objcopy")
    )
    result.add_argument(
        "--site-tool",
        default=os.environ.get("RISCV_IRQ_SITE_TOOL"),
        help="also validate the linked image with llvm-riscv-irq-sites",
    )
    return result


def main() -> int:
    arguments = parser().parse_args()
    with tempfile.TemporaryDirectory(prefix="riscv-site-map-") as temporary:
        directory = pathlib.Path(temporary)
        baseline_obj, baseline_elf = build(
            arguments, INPUTS / "baseline.S", "baseline", directory
        )
        mapped_obj, mapped_elf = build(
            arguments, INPUTS / "mapped.S", "mapped", directory
        )

        baseline_obj_text = dump_section(
            arguments.llvm_objcopy, baseline_obj, ".text", directory / "base-o.text"
        )
        mapped_obj_text = dump_section(
            arguments.llvm_objcopy, mapped_obj, ".text", directory / "map-o.text"
        )
        baseline_elf_text = dump_section(
            arguments.llvm_objcopy, baseline_elf, ".text", directory / "base-e.text"
        )
        mapped_elf_text = dump_section(
            arguments.llvm_objcopy, mapped_elf, ".text", directory / "map-e.text"
        )
        if baseline_obj_text != mapped_obj_text:
            raise AssertionError("object .text differs with map records enabled")
        if baseline_elf_text != mapped_elf_text:
            raise AssertionError("linked .text differs with map records enabled")

        raw_sites = dump_section(
            arguments.llvm_objcopy,
            mapped_elf,
            ".riscv.linux_irq_sites",
            directory / "sites.bin",
        )
        records = site.decode_records(raw_sites, "little")
        expected = [
            (2, 0x80000004, 0x00112233445566778899AABBCCDDEEFF),
            (3, 0x80000008, 0xFFEEDDCCBBAA99887766554433221100),
        ]
        observed = [(r.kind, r.address, r.site_id) for r in records]
        if observed != expected:
            raise AssertionError(f"site records differ: {observed!r}")

        sidecar = None
        if arguments.site_tool:
            site_tool = str(pathlib.Path(arguments.site_tool).resolve())
            result = run_captured([
                site_tool,
                "--load-bias=0x1000",
                str(mapped_elf),
            ])
            if result.returncode:
                raise AssertionError(
                    f"site tool rejected a valid linked image:\n{result.stderr}"
                )
            sidecar = json.loads(result.stdout)
            if sidecar["schema"] != 1 or sidecar["record_size"] != 32:
                raise AssertionError(f"unexpected sidecar schema: {sidecar!r}")
            if sidecar["artifact_kind"] != "linked-image":
                raise AssertionError("linked ELF has the wrong artifact kind")
            if sidecar["trigger_phase"] != site.TRIGGER_PHASE:
                raise AssertionError("sidecar trigger phase differs from map format")
            if sidecar["default_hit_count_scope"] != "per-vcpu":
                raise AssertionError("sidecar hit-count scope is not per-vCPU")
            if sidecar["image"]["arch"] != "riscv64":
                raise AssertionError("sidecar does not identify an RV64 image")
            image_hash = hashlib.sha256(mapped_elf.read_bytes()).hexdigest()
            if sidecar["image"]["sha256"] != image_hash:
                raise AssertionError("sidecar image digest is incorrect")

            expected_sites = [
                {
                    "site_id": f"{record.site_id:032x}",
                    "kind_name": site.SITE_KIND_NAMES[record.kind],
                    "link_va": f"0x{record.address:016x}",
                    "runtime_va": f"0x{record.address + 0x1000:016x}",
                    "symbol": "_start",
                    "symbol_offset": f"0x{record.address - 0x80000000:016x}",
                }
                for record in records
            ]
            observed_sites = [
                {key: value for key, value in entry.items()
                 if key in {
                     "site_id", "kind_name", "link_va", "runtime_va",
                     "symbol", "symbol_offset",
                 }}
                for entry in sidecar["sites"]
            ]
            if observed_sites != expected_sites:
                raise AssertionError(
                    f"sidecar site addresses differ: {observed_sites!r}"
                )

            rejected = run_captured([site_tool, str(mapped_obj)])
            if rejected.returncode == 0:
                raise AssertionError(
                    "linked-image mode accepted a relocatable object"
                )
            if "linked-image mode requires a linked ELF" not in rejected.stderr:
                raise AssertionError(
                    f"unexpected relocatable rejection: {rejected.stderr!r}"
                )

            relocatable_result = run_captured([
                site_tool,
                "--validate-relocatable",
                str(mapped_obj),
            ])
            if relocatable_result.returncode:
                raise AssertionError(
                    "site tool rejected valid object relocations:\n"
                    f"{relocatable_result.stderr}"
                )
            relocatable = json.loads(relocatable_result.stdout)
            if relocatable["artifact_kind"] != "relocatable-object":
                raise AssertionError("object has the wrong artifact kind")
            relocation_sites = [
                (entry["relocation_type"], entry["text_section"],
                 entry["text_section_offset"])
                for entry in relocatable["sites"]
            ]
            if relocation_sites != [
                ("R_RISCV_64", ".text", "0x0000000000000004"),
                ("R_RISCV_64", ".text", "0x0000000000000008"),
            ]:
                raise AssertionError(
                    f"object relocation validation differs: {relocation_sites!r}"
                )

            malformed_obj = assemble(
                arguments,
                INPUTS / "bad-relocation.S",
                "bad-relocation",
                directory,
            )
            malformed = run_captured([
                site_tool,
                "--validate-relocatable",
                str(malformed_obj),
            ])
            if malformed.returncode == 0:
                raise AssertionError("site tool accepted an R_RISCV_32 address")
            if "site address requires R_RISCV_64" not in malformed.stderr:
                raise AssertionError(
                    f"unexpected malformed-relocation error: {malformed.stderr!r}"
                )

        print(json.dumps({
            "result": "PASS",
            "target": "riscv64-unknown-elf",
            "text_bytes": len(mapped_elf_text),
            "site_record_size": site.SITE_RECORD_SIZE,
            "site_count": len(records),
            "sidecar_validated": sidecar is not None,
            "trigger_phase": site.TRIGGER_PHASE,
            "sites": [record.to_json() for record in records],
        }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
