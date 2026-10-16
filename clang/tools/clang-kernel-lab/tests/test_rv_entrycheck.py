#!/usr/bin/env python3
"""Exercise linked RV64 entry-checker controls and fail-closed gates."""

from __future__ import annotations

import argparse
import copy
import json
import pathlib
import subprocess
import tempfile


HERE = pathlib.Path(__file__).resolve().parent
TOOL = HERE.parent
SOURCE = HERE / "entrycheck-probe.S"
LINKER_SCRIPT = HERE / "entrycheck-link.ld"
POLICY = TOOL / "examples" / "riscv-entrycheck-v1.json"


def run(command: list[str], *, expect: int = 0) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != expect:
        raise AssertionError(
            f"command returned {result.returncode}, expected {expect}: "
            f"{' '.join(command)}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def compile_fixture(arguments: argparse.Namespace, output: pathlib.Path,
                    *, define: str | None) -> None:
    command = [
        str(arguments.clang),
        "--target=riscv64-linux-gnu",
        "-march=rv64imac",
        "-mabi=lp64",
        "-c",
        str(SOURCE),
        "-o",
        str(output),
    ]
    if define:
        command.insert(-2, f"-D{define}=1")
    run(command)


def link_fixture(arguments: argparse.Namespace, source: pathlib.Path,
                 output: pathlib.Path, *, relax: bool) -> None:
    command = [
        str(arguments.ld_lld),
        "-m",
        "elf64lriscv",
        "-T",
        str(LINKER_SCRIPT),
        str(source),
        "-o",
        str(output),
    ]
    if not relax:
        command.insert(1, "--no-relax")
    run(command)


def check_document(document: dict[str, object],
                   *, expected_rule: str | None) -> None:
    expected = "FAIL" if expected_rule else "PASS"
    if document.get("result") != expected:
        raise AssertionError(f"entry checker returned {document.get('result')}")
    if document.get("scope") != "direct-calls-in-entry-regions-v1":
        raise AssertionError("entry checker reported an unexpected scope")
    findings = document.get("findings")
    if not isinstance(findings, list):
        raise AssertionError("entry checker omitted findings")
    if expected_rule:
        if len(findings) != 1:
            raise AssertionError(
                f"negative fixture has {len(findings)} findings"
            )
        finding = findings[0]
        if finding.get("rule") != expected_rule:
            raise AssertionError(f"unexpected negative finding: {finding}")
        if expected_rule == "forbidden-call" and finding.get(
                "matched_symbol") != "__sanitizer_cov_trace_pc":
            raise AssertionError(f"unexpected forbidden symbol: {finding}")
    elif findings:
        raise AssertionError(f"control fixture has findings: {findings}")
    regions = document.get("resolved_regions")
    if not isinstance(regions, list) or len(regions) != 1:
        raise AssertionError(f"entry checker resolved unexpected regions: {regions}")
    region = regions[0]
    if region.get("name") != "noinstr" or region.get("section") != ".text":
        raise AssertionError(f"entry checker resolved the wrong region: {region}")
    if not region.get("source", "").startswith("symbols:"):
        raise AssertionError(f"entry checker did not use symbol bounds: {region}")


def write_policy(path: pathlib.Path, document: dict[str, object]) -> None:
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")


def check_invalid_policies(arguments: argparse.Namespace, image: pathlib.Path,
                           root: pathlib.Path) -> dict[str, object]:
    policy = json.loads(POLICY.read_text())
    cases = []

    unknown_field = copy.deepcopy(policy)
    unknown_field["unexpected"] = True
    cases.append(("unknown-field", unknown_field, "unknown policy field"))

    allow_unknown = copy.deepcopy(policy)
    allow_unknown["reject_unknown_calls"] = False
    cases.append(("allow-unknown", allow_unknown,
                  "requires reject_unknown_calls=true"))

    wrong_range_type = copy.deepcopy(policy)
    wrong_range_type["entry_symbol_ranges"] = "noinstr"
    cases.append(("wrong-range-type", wrong_range_type,
                  "entry_symbol_ranges must be an array"))

    duplicate_range = copy.deepcopy(policy)
    duplicate_range["entry_symbol_ranges"].append(
        copy.deepcopy(duplicate_range["entry_symbol_ranges"][0]))
    cases.append(("duplicate-range", duplicate_range,
                  "entry_symbol_ranges contains a duplicate name"))

    empty_forbidden = copy.deepcopy(policy)
    empty_forbidden["forbidden_symbols"] = []
    cases.append(("empty-forbidden", empty_forbidden,
                  "forbidden_symbols must contain"))

    duplicate_region_name = copy.deepcopy(policy)
    duplicate_region_name["entry_sections"] = ["noinstr"]
    cases.append(("duplicate-region-name", duplicate_region_name,
                  "entry regions must have unique names"))

    receipts = {}
    for name, document, expected_error in cases:
        policy_path = root / f"policy-{name}.json"
        write_policy(policy_path, document)
        result = run(
            [str(arguments.checker), "--policy", str(policy_path), str(image)],
            expect=2,
        )
        if expected_error not in result.stderr:
            raise AssertionError(
                f"{name} did not report {expected_error!r}: {result.stderr}"
            )
        receipts[name] = {"result": "REJECTED", "diagnostic": expected_error}
    return receipts


def check_section_mode(arguments: argparse.Namespace,
                       images: dict[str, pathlib.Path],
                       root: pathlib.Path) -> dict[str, object]:
    policy = json.loads(POLICY.read_text())
    del policy["entry_symbol_ranges"]
    policy["entry_sections"] = [".text"]
    policy_path = root / "policy-section.json"
    write_policy(policy_path, policy)

    receipts = {}
    for name, expected_rule in (("good-relax", None),
                                ("bad-relax", "forbidden-call")):
        result = run(
            [str(arguments.checker), "--policy", str(policy_path),
             str(images[name])],
            expect=1 if expected_rule else 0,
        )
        document = json.loads(result.stdout)
        findings = document.get("findings")
        expected_result = "FAIL" if expected_rule else "PASS"
        if document.get("result") != expected_result or not isinstance(
                findings, list):
            raise AssertionError(f"section mode returned bad output: {document}")
        if expected_rule:
            if len(findings) != 1 or findings[0].get("rule") != expected_rule:
                raise AssertionError(f"section mode missed callback: {findings}")
        elif findings:
            raise AssertionError(f"section control has findings: {findings}")
        regions = document.get("resolved_regions")
        if not isinstance(regions, list) or len(regions) != 1:
            raise AssertionError(f"section mode resolved bad regions: {regions}")
        if regions[0].get("name") != ".text" or regions[0].get(
                "source") != "section:.text":
            raise AssertionError(f"section mode resolved bad region: {regions}")
        receipts[name] = {
            "result": document["result"],
            "coverage": document["coverage"],
            "findings": findings,
        }
    return receipts


def check_boundary_failure(arguments: argparse.Namespace, image: pathlib.Path,
                           root: pathlib.Path) -> dict[str, object]:
    policy = json.loads(POLICY.read_text())
    policy["entry_symbol_ranges"][0]["start_symbol"] = "__missing_start"
    policy_path = root / "policy-missing-boundary.json"
    write_policy(policy_path, policy)
    result = run(
        [str(arguments.checker), "--policy", str(policy_path), str(image)],
        expect=1,
    )
    document = json.loads(result.stdout)
    findings = document.get("findings")
    if document.get("result") != "FAIL" or not isinstance(findings, list):
        raise AssertionError(f"missing boundary did not fail closed: {document}")
    if len(findings) != 1 or findings[0].get(
            "rule") != "unresolved-entry-boundary":
        raise AssertionError(f"unexpected missing-boundary result: {findings}")
    if document.get("resolved_regions") != []:
        raise AssertionError("missing boundary unexpectedly resolved a region")
    return {
        "result": document["result"],
        "findings": findings,
    }


def check_overlapping_regions(arguments: argparse.Namespace,
                              image: pathlib.Path,
                              root: pathlib.Path) -> dict[str, object]:
    policy = json.loads(POLICY.read_text())
    policy["entry_sections"] = [".text"]
    policy_path = root / "policy-overlap.json"
    write_policy(policy_path, policy)
    result = run(
        [str(arguments.checker), "--policy", str(policy_path), str(image)],
        expect=1,
    )
    document = json.loads(result.stdout)
    findings = document.get("findings")
    if document.get("result") != "FAIL" or not isinstance(findings, list):
        raise AssertionError(f"overlapping regions did not fail: {document}")
    if len(findings) != 1 or findings[0].get(
            "rule") != "overlapping-entry-regions":
        raise AssertionError(f"unexpected overlap result: {findings}")
    return {
        "result": document["result"],
        "findings": findings,
    }


def check_invalid_images(arguments: argparse.Namespace,
                         relocatable: pathlib.Path,
                         root: pathlib.Path) -> dict[str, object]:
    result = run(
        [str(arguments.checker), "--policy", str(POLICY), str(relocatable)],
        expect=2,
    )
    linked_error = "entry checking requires a linked ELF image"
    if linked_error not in result.stderr:
        raise AssertionError(f"relocatable input did not fail closed: {result.stderr}")

    rv32_object = root / "rv32.o"
    run([
        str(arguments.clang),
        "--target=riscv32-linux-gnu",
        "-march=rv32imac",
        "-mabi=ilp32",
        "-c",
        str(SOURCE),
        "-o",
        str(rv32_object),
    ])
    rv32_image = root / "rv32.elf"
    run([
        str(arguments.ld_lld),
        "-m",
        "elf32lriscv",
        "-T",
        str(LINKER_SCRIPT),
        str(rv32_object),
        "-o",
        str(rv32_image),
    ])
    result = run(
        [str(arguments.checker), "--policy", str(POLICY), str(rv32_image)],
        expect=2,
    )
    arch_error = "version one requires an RV64 ELF image"
    if arch_error not in result.stderr:
        raise AssertionError(f"RV32 input did not fail closed: {result.stderr}")
    return {
        "relocatable": {"result": "REJECTED", "diagnostic": linked_error},
        "rv32": {"result": "REJECTED", "diagnostic": arch_error},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clang", required=True, type=pathlib.Path)
    parser.add_argument("--ld-lld", required=True, type=pathlib.Path)
    parser.add_argument("--checker", required=True, type=pathlib.Path)
    arguments = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="rv-entrycheck-") as temporary:
        root = pathlib.Path(temporary)
        objects = {}
        fixtures = (
            ("good", None, None),
            ("bad", "ENTRYCHECK_BAD", "forbidden-call"),
            ("unknown", "ENTRYCHECK_UNKNOWN", "unknown-call"),
        )
        for name, define, _ in fixtures:
            output = root / f"{name}.o"
            compile_fixture(arguments, output, define=define)
            objects[name] = output

        receipts = {}
        images = {}
        for relax in (False, True):
            mode = "relax" if relax else "no-relax"
            for name, _, expected_rule in fixtures:
                image = root / f"{name}-{mode}.elf"
                link_fixture(arguments, objects[name], image, relax=relax)
                images[f"{name}-{mode}"] = image
                result = run(
                    [
                        str(arguments.checker),
                        "--policy",
                        str(POLICY),
                        str(image),
                    ],
                    expect=1 if expected_rule else 0,
                )
                document = json.loads(result.stdout)
                check_document(document, expected_rule=expected_rule)
                receipts[f"{name}-{mode}"] = {
                    "result": document["result"],
                    "coverage": document["coverage"],
                    "findings": document["findings"],
                }

        policy_receipts = check_invalid_policies(
            arguments, images["good-no-relax"], root
        )
        boundary_receipt = check_boundary_failure(
            arguments, images["good-no-relax"], root
        )
        section_receipts = check_section_mode(arguments, images, root)
        overlap_receipt = check_overlapping_regions(
            arguments, images["good-no-relax"], root
        )
        invalid_image_receipts = check_invalid_images(
            arguments, objects["good"], root
        )

        print(json.dumps({
            "result": "PASS",
            "lanes": receipts,
            "invalid_policies": policy_receipts,
            "missing_boundary": boundary_receipt,
            "section_mode": section_receipts,
            "overlapping_regions": overlap_receipt,
            "invalid_images": invalid_image_receipts,
        }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
