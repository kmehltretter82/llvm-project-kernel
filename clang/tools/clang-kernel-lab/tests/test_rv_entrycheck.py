#!/usr/bin/env python3
"""Exercise linked RV64 entry-checker controls and fail-closed gates."""

from __future__ import annotations

import argparse
import collections
import copy
import hashlib
import json
import pathlib
import subprocess
import tempfile


HERE = pathlib.Path(__file__).resolve().parent
TOOL = HERE.parent
SOURCE = HERE / "entrycheck-probe.S"
LINKER_SCRIPT = HERE / "entrycheck-link.ld"
POLICY = TOOL / "examples" / "riscv-entrycheck-v1.json"
INDIRECT_POLICY = TOOL / "examples" / "riscv-entrycheck-indirect-v2.json"
TRANSITIVE_POLICY = TOOL / "examples" / "riscv-entrycheck-transitive-v3.json"
LINUX_POLICY_V1 = TOOL / "examples" / "riscv-linux-entrycheck-v1.json"
LINUX_POLICY_V2 = TOOL / "examples" / "riscv-linux-entrycheck-v2.json"
LINUX_POLICY_V3 = TOOL / "examples" / "riscv-linux-entrycheck-v3.json"


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


def check_call_path(record: dict[str, object],
                    expected_names: list[str]) -> None:
    names = record.get("call_path")
    addresses = record.get("call_path_vas")
    callsites = record.get("call_path_callsites")
    if names != expected_names or not isinstance(addresses, list) or len(
            addresses) != len(expected_names) or not isinstance(
            callsites, list) or len(callsites) != len(expected_names) - 1:
        raise AssertionError(f"invalid call path identity: {record}")
    if not all(isinstance(address, str) and address.startswith("0x") and
               len(address) == 18 for address in addresses + callsites):
        raise AssertionError(f"invalid call path address: {record}")
    reached_from = record.get("reached_from_va")
    if reached_from is not None and (
            not callsites or callsites[-1] != reached_from):
        raise AssertionError(f"call path lost its incoming edge: {record}")


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
                  "require reject_unknown_calls=true"))

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

    schema_one_indirect = copy.deepcopy(policy)
    schema_one_indirect["indirect_call_targets"] = []
    cases.append(("schema-one-indirect", schema_one_indirect,
                  "unknown policy field"))

    schema_two_missing = copy.deepcopy(policy)
    schema_two_missing["schema"] = 2
    cases.append(("schema-two-missing", schema_two_missing,
                  "schema two requires 1 through 256 indirect call"))

    schema_two_wrong_type = copy.deepcopy(policy)
    schema_two_wrong_type["schema"] = 2
    schema_two_wrong_type["indirect_call_targets"] = "entry_path"
    cases.append(("schema-two-wrong-type", schema_two_wrong_type,
                  "indirect_call_targets must be an array"))

    schema_three_missing = copy.deepcopy(policy)
    schema_three_missing["schema"] = 3
    cases.append(("schema-three-missing", schema_three_missing,
                  "schema three requires 0 through 4096 indirect call"))

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

    duplicate_key_path = root / "policy-duplicate-json-key.json"
    duplicate_key_path.write_text(
        '{\n  "sche\\u006da": 2,' + POLICY.read_text()[1:]
    )
    duplicate_key_error = "duplicate object keys or excessive nesting"
    result = run(
        [str(arguments.checker), "--policy", str(duplicate_key_path), str(image)],
        expect=2,
    )
    if duplicate_key_error not in result.stderr:
        raise AssertionError(
            "escaped duplicate JSON key did not fail closed: " + result.stderr
        )
    receipts["duplicate-json-key"] = {
        "result": "REJECTED",
        "diagnostic": duplicate_key_error,
    }
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
    arch_error = "entry checking requires an RV64 ELF image"
    if arch_error not in result.stderr:
        raise AssertionError(f"RV32 input did not fail closed: {result.stderr}")
    return {
        "relocatable": {"result": "REJECTED", "diagnostic": linked_error},
        "rv32": {"result": "REJECTED", "diagnostic": arch_error},
    }


def check_indirect_policies(arguments: argparse.Namespace,
                            images: dict[str, pathlib.Path],
                            root: pathlib.Path) -> dict[str, object]:
    receipts = {}
    for name in ("unknown-no-relax", "unknown-relax"):
        result = run([
            str(arguments.checker),
            "--policy",
            str(INDIRECT_POLICY),
            str(images[name]),
        ])
        document = json.loads(result.stdout)
        if document.get("result") != "PASS" or document.get(
                "scope") != "site-scoped-indirect-targets-v2":
            raise AssertionError(f"indirect policy did not pass: {document}")
        if document.get("findings") != []:
            raise AssertionError(f"approved indirect call has findings: {document}")
        coverage = document.get("coverage")
        if not isinstance(coverage, dict) or coverage.get(
                "policy_resolved_indirect_calls") != 1 or coverage.get(
                "indirect_target_edges") != 1 or coverage.get(
                "unknown_calls") != 0:
            raise AssertionError(f"bad indirect-call coverage: {coverage}")
        resolved = document.get("resolved_indirect_calls")
        if not isinstance(resolved, list) or len(resolved) != 1:
            raise AssertionError(f"bad resolved indirect calls: {resolved}")
        if not resolved[0].get("used") or resolved[0].get(
                "caller_symbol") != "entry_path_alias":
            raise AssertionError(f"indirect callsite was not consumed: {resolved}")
        targets = resolved[0].get("targets")
        if not isinstance(targets, list) or len(targets) != 1 or targets[0].get(
                "symbol") != "entrycheck_safe_alias":
            raise AssertionError(f"wrong indirect targets: {targets}")
        receipts[name] = {
            "result": document["result"],
            "coverage": coverage,
            "resolved_indirect_calls": resolved,
        }

    policy = json.loads(INDIRECT_POLICY.read_text())
    policy["expected_image"] = {
        "sha256": hashlib.sha256(images["unknown-relax"].read_bytes()).hexdigest(),
        "build_id": None,
    }
    bound_path = root / "policy-indirect-bound.json"
    write_policy(bound_path, policy)
    result = run([
        str(arguments.checker), "--policy", str(bound_path),
        str(images["unknown-relax"]),
    ])
    document = json.loads(result.stdout)
    policy_receipt = document.get("policy")
    if document.get("result") != "PASS" or not isinstance(
            policy_receipt, dict) or not policy_receipt.get("identity_bound"):
        raise AssertionError(f"matching image identity did not pass: {document}")
    receipts["matching-image"] = {
        "result": document["result"],
        "expected_image": policy_receipt["expected_image"],
    }

    policy["expected_image"]["sha256"] = "0" * 64
    mismatch_path = root / "policy-indirect-image-mismatch.json"
    write_policy(mismatch_path, policy)
    result = run([
        str(arguments.checker), "--policy", str(mismatch_path),
        str(images["unknown-relax"]),
    ], expect=1)
    document = json.loads(result.stdout)
    mismatch_findings = document.get("findings")
    if not isinstance(mismatch_findings, list) or len(mismatch_findings) != 1 \
            or mismatch_findings[0].get("rule") != "image-sha256-mismatch":
        raise AssertionError(f"wrong image identity did not fail: {document}")
    receipts["wrong-image"] = {
        "result": document["result"],
        "findings": mismatch_findings,
    }

    policy["expected_image"]["sha256"] = hashlib.sha256(
        images["unknown-relax"].read_bytes()).hexdigest()
    policy["expected_image"]["build_id"] = "00"
    build_id_path = root / "policy-indirect-build-id-mismatch.json"
    write_policy(build_id_path, policy)
    result = run([
        str(arguments.checker), "--policy", str(build_id_path),
        str(images["unknown-relax"]),
    ], expect=1)
    document = json.loads(result.stdout)
    build_id_findings = document.get("findings")
    if not isinstance(build_id_findings, list) or len(build_id_findings) != 1 \
            or build_id_findings[0].get("rule") != "image-build-id-mismatch":
        raise AssertionError(f"wrong build ID did not fail: {document}")
    receipts["wrong-build-id"] = {
        "result": document["result"],
        "findings": build_id_findings,
    }

    policy = json.loads(INDIRECT_POLICY.read_text())
    policy["indirect_call_targets"][0]["target_symbols"] = [
        "entrycheck_callback_impl"
    ]
    forbidden_path = root / "policy-indirect-forbidden.json"
    write_policy(forbidden_path, policy)
    result = run([
        str(arguments.checker), "--policy", str(forbidden_path),
        str(images["unknown-relax"]),
    ], expect=1)
    document = json.loads(result.stdout)
    rules = {finding.get("rule") for finding in document.get("findings", [])}
    if rules != {"forbidden-indirect-target", "unknown-call"}:
        raise AssertionError(f"forbidden target was laundered: {document}")
    receipts["forbidden-target"] = {
        "result": document["result"],
        "rules": sorted(rules),
    }

    policy = json.loads(INDIRECT_POLICY.read_text())
    policy["indirect_call_targets"][0]["target_symbols"] = [
        "entrycheck_missing_target"
    ]
    missing_target_path = root / "policy-indirect-missing-target.json"
    write_policy(missing_target_path, policy)
    result = run([
        str(arguments.checker), "--policy", str(missing_target_path),
        str(images["unknown-relax"]),
    ], expect=1)
    document = json.loads(result.stdout)
    rules = {finding.get("rule") for finding in document.get("findings", [])}
    if rules != {"unresolved-indirect-target", "unknown-call"}:
        raise AssertionError(f"missing target was accepted: {document}")
    receipts["missing-target"] = {
        "result": document["result"],
        "rules": sorted(rules),
    }

    policy = json.loads(INDIRECT_POLICY.read_text())
    policy["indirect_call_targets"][0]["instruction_offset"] = 64
    outside_caller_path = root / "policy-indirect-outside-caller.json"
    write_policy(outside_caller_path, policy)
    result = run([
        str(arguments.checker), "--policy", str(outside_caller_path),
        str(images["unknown-relax"]),
    ], expect=1)
    document = json.loads(result.stdout)
    rules = {finding.get("rule") for finding in document.get("findings", [])}
    if rules != {"invalid-indirect-callsite", "unknown-call"}:
        raise AssertionError(f"out-of-range callsite was accepted: {document}")
    receipts["outside-caller"] = {
        "result": document["result"],
        "rules": sorted(rules),
    }

    stale_result = run([
        str(arguments.checker), "--policy", str(INDIRECT_POLICY),
        str(images["good-relax"]),
    ], expect=1)
    stale_document = json.loads(stale_result.stdout)
    stale_findings = stale_document.get("findings")
    if not isinstance(stale_findings, list) or len(stale_findings) != 1 or \
            stale_findings[0].get("rule") != "unused-indirect-callsite":
        raise AssertionError(f"stale callsite policy did not fail: {stale_document}")
    receipts["stale-callsite"] = {
        "result": stale_document["result"],
        "findings": stale_findings,
    }

    policy = json.loads(INDIRECT_POLICY.read_text())
    policy["indirect_call_targets"].append(
        copy.deepcopy(policy["indirect_call_targets"][0]))
    duplicate_path = root / "policy-indirect-duplicate.json"
    write_policy(duplicate_path, policy)
    duplicate_result = run([
        str(arguments.checker), "--policy", str(duplicate_path),
        str(images["unknown-relax"]),
    ], expect=2)
    duplicate_error = "indirect call target rules contain a duplicate site"
    if duplicate_error not in duplicate_result.stderr:
        raise AssertionError(
            f"duplicate indirect policy did not fail: {duplicate_result.stderr}"
        )
    receipts["duplicate-callsite"] = {
        "result": "REJECTED",
        "diagnostic": duplicate_error,
    }

    policy = json.loads(INDIRECT_POLICY.read_text())
    policy["indirect_call_targets"][0]["target_symbols"].append(
        "entrycheck_safe_alias")
    duplicate_target_path = root / "policy-indirect-duplicate-target.json"
    write_policy(duplicate_target_path, policy)
    duplicate_target_result = run([
        str(arguments.checker), "--policy", str(duplicate_target_path),
        str(images["unknown-relax"]),
    ], expect=2)
    duplicate_target_error = "indirect call target rule contains a duplicate"
    if duplicate_target_error not in duplicate_target_result.stderr:
        raise AssertionError(
            "duplicate indirect target did not fail: "
            f"{duplicate_target_result.stderr}"
        )
    receipts["duplicate-target"] = {
        "result": "REJECTED",
        "diagnostic": duplicate_target_error,
    }

    policy = json.loads(INDIRECT_POLICY.read_text())
    policy["indirect_call_targets"][0]["target_symbols"].append(
        "entrycheck_safe_target")
    duplicate_address_path = root / "policy-indirect-duplicate-address.json"
    write_policy(duplicate_address_path, policy)
    duplicate_address_result = run([
        str(arguments.checker), "--policy", str(duplicate_address_path),
        str(images["unknown-relax"]),
    ], expect=1)
    duplicate_address_document = json.loads(duplicate_address_result.stdout)
    rules = {
        finding.get("rule")
        for finding in duplicate_address_document.get("findings", [])
    }
    if rules != {"duplicate-indirect-target-address", "unknown-call"}:
        raise AssertionError(
            "duplicate linked target address did not fail: "
            f"{duplicate_address_document}"
        )
    receipts["duplicate-target-address"] = {
        "result": duplicate_address_document["result"],
        "rules": sorted(rules),
    }
    return receipts


def check_transitive_policies(arguments: argparse.Namespace,
                              images: dict[str, pathlib.Path],
                              root: pathlib.Path) -> dict[str, object]:
    cases = (
        ("transitive-good", None, 2, 2, None),
        ("transitive-bad", "forbidden-call", 1, 1,
         ["noinstr", "entrycheck_middle"]),
        ("transitive-unknown", "unknown-call", 1, 1,
         ["noinstr", "entrycheck_middle"]),
        ("transitive-zero-size", "unresolved-transitive-function-range", 1, 1,
         ["noinstr", "entrycheck_middle", "entrycheck_zero_size"]),
        ("transitive-cycle", None, 1, 1, None),
    )
    receipts = {}
    for relax in (False, True):
        mode = "relax" if relax else "no-relax"
        for name, expected_rule, expected_functions, expected_depth, path in cases:
            result = run([
                str(arguments.checker),
                "--policy",
                str(TRANSITIVE_POLICY),
                str(images[f"{name}-{mode}"]),
            ], expect=1 if expected_rule else 0)
            document = json.loads(result.stdout)
            if document.get("scope") != "transitive-call-graph-v3":
                raise AssertionError(f"transitive scope changed: {document}")
            findings = document.get("findings")
            if not isinstance(findings, list):
                raise AssertionError(f"transitive findings missing: {document}")
            if expected_rule:
                if len(findings) != 1 or findings[0].get("rule") != expected_rule:
                    raise AssertionError(
                        f"{name}-{mode} returned wrong findings: {findings}"
                    )
                check_call_path(findings[0], path)
            elif findings:
                raise AssertionError(
                    f"{name}-{mode} control has findings: {findings}"
                )
            coverage = document.get("coverage")
            if not isinstance(coverage, dict) or coverage.get(
                    "transitive_functions") != expected_functions or coverage.get(
                    "max_call_depth_reached") != expected_depth or coverage.get(
                    "root_regions") != 1:
                raise AssertionError(
                    f"{name}-{mode} returned wrong coverage: {coverage}"
                )
            functions = document.get("resolved_transitive_functions")
            if not isinstance(functions, list) or len(
                    functions) != expected_functions:
                raise AssertionError(
                    f"{name}-{mode} returned wrong functions: {functions}"
                )
            if not functions or functions[0].get(
                    "symbol") != "entrycheck_middle":
                raise AssertionError(
                    f"{name}-{mode} missed the middle function: {functions}"
                )
            if name == "transitive-good" and (
                    functions[1].get("symbol") != "entrycheck_safe_target" or
                    functions[1].get("call_path") != [
                        "noinstr", "entrycheck_middle", "entrycheck_safe_target"
                    ]):
                raise AssertionError(
                    f"{name}-{mode} returned the wrong complete path: {functions}"
                )
            for function in functions:
                check_call_path(function, function["call_path"])
            receipts[f"{name}-{mode}"] = {
                "result": document["result"],
                "coverage": coverage,
                "findings": findings,
                "resolved_transitive_functions": functions,
            }

    indirect_policy = json.loads(INDIRECT_POLICY.read_text())
    indirect_policy["schema"] = 3
    indirect_path = root / "policy-indirect-transitive.json"
    write_policy(indirect_path, indirect_policy)
    for mode in ("no-relax", "relax"):
        result = run([
            str(arguments.checker),
            "--policy",
            str(indirect_path),
            str(images[f"unknown-{mode}"]),
        ])
        document = json.loads(result.stdout)
        coverage = document.get("coverage")
        functions = document.get("resolved_transitive_functions")
        if document.get("result") != "PASS" or document.get("findings") != []:
            raise AssertionError(
                f"transitive indirect control failed: {document}"
            )
        if not isinstance(coverage, dict) or coverage.get(
                "policy_resolved_indirect_calls") != 1 or coverage.get(
                "indirect_target_edges") != 1 or coverage.get(
                "transitive_functions") != 1 or coverage.get(
                "unknown_calls") != 0:
            raise AssertionError(
                f"transitive indirect coverage changed: {coverage}"
            )
        if not isinstance(functions, list) or len(functions) != 1 or functions[
                0].get("symbol") != "entrycheck_safe_alias" or functions[0].get(
                "call_path") != ["noinstr", "entrycheck_safe_alias"]:
            raise AssertionError(
                f"transitive indirect target was not scanned: {functions}"
            )
        check_call_path(functions[0], ["noinstr", "entrycheck_safe_alias"])
        receipts[f"indirect-{mode}"] = {
            "result": document["result"],
            "coverage": coverage,
            "resolved_transitive_functions": functions,
        }

    callee_policy = json.loads(TRANSITIVE_POLICY.read_text())
    callee_policy["indirect_call_targets"] = [{
        "caller_symbol": "entrycheck_middle",
        "instruction_offset": 0,
        "target_symbols": ["entrycheck_safe_alias"],
    }]
    callee_path = root / "policy-transitive-callee-indirect.json"
    write_policy(callee_path, callee_policy)
    for mode in ("no-relax", "relax"):
        result = run([
            str(arguments.checker),
            "--policy",
            str(callee_path),
            str(images[f"transitive-unknown-{mode}"]),
        ])
        document = json.loads(result.stdout)
        coverage = document.get("coverage")
        functions = document.get("resolved_transitive_functions")
        if document.get("result") != "PASS" or document.get("findings") != []:
            raise AssertionError(
                f"callee indirect policy failed: {document}"
            )
        if not isinstance(coverage, dict) or coverage.get(
                "policy_resolved_indirect_calls") != 1 or coverage.get(
                "indirect_target_edges") != 1 or coverage.get(
                "transitive_functions") != 2 or coverage.get(
                "unknown_calls") != 0:
            raise AssertionError(
                f"callee indirect coverage changed: {coverage}"
            )
        if not isinstance(functions, list) or len(functions) != 2 or functions[
                1].get("symbol") != "entrycheck_safe_alias":
            raise AssertionError(
                f"callee indirect target was not scanned: {functions}"
            )
        check_call_path(
            functions[1],
            ["noinstr", "entrycheck_middle", "entrycheck_safe_alias"],
        )
        receipts[f"callee-indirect-{mode}"] = {
            "result": document["result"],
            "coverage": coverage,
            "resolved_transitive_functions": functions,
        }
    return receipts


def check_linux_image(arguments: argparse.Namespace) -> dict[str, object]:
    v1_result = run([
        str(arguments.checker), "--policy", str(LINUX_POLICY_V1),
        str(arguments.linux_image),
    ], expect=1)
    v1 = json.loads(v1_result.stdout)
    v1_findings = v1.get("findings")
    expected_unknowns = {
        "0xffffffff800ea184",
        "0xffffffff800ea1c8",
        "0xffffffff800ea2ec",
        "0xffffffff800ed6ac",
    }
    if not isinstance(v1_findings, list) or {
            finding.get("instruction_va") for finding in v1_findings
    } != expected_unknowns or {
            finding.get("rule") for finding in v1_findings
    } != {"unknown-call"}:
        raise AssertionError(f"schema-one Linux discovery changed: {v1}")
    v1_coverage = v1.get("coverage")
    if not isinstance(v1_coverage, dict) or v1_coverage.get("calls") != 106 or \
            v1_coverage.get("resolved_calls") != 102 or v1_coverage.get(
                "unknown_calls") != 4:
        raise AssertionError(f"schema-one Linux coverage changed: {v1_coverage}")

    v2_result = run([
        str(arguments.checker), "--policy", str(LINUX_POLICY_V2),
        str(arguments.linux_image),
    ])
    v2 = json.loads(v2_result.stdout)
    v2_coverage = v2.get("coverage")
    if v2.get("result") != "PASS" or v2.get("findings") != [] or not isinstance(
            v2_coverage, dict):
        raise AssertionError(f"schema-two Linux audit failed: {v2}")
    expected_coverage = {
        "bytes": 2840,
        "calls": 106,
        "indirect_target_edges": 22,
        "instructions": 1053,
        "policy_resolved_indirect_calls": 4,
        "regions": 3,
        "resolved_calls": 106,
        "unknown_calls": 0,
    }
    if v2_coverage != expected_coverage:
        raise AssertionError(f"schema-two Linux coverage changed: {v2_coverage}")
    v2_policy = v2.get("policy")
    if not isinstance(v2_policy, dict) or not v2_policy.get("identity_bound"):
        raise AssertionError(f"schema-two Linux policy is not image-bound: {v2}")
    resolved = v2.get("resolved_indirect_calls")
    if not isinstance(resolved, list) or len(resolved) != 4 or not all(
            rule.get("used") for rule in resolved):
        raise AssertionError(f"schema-two Linux callsites changed: {resolved}")
    if {rule.get("instruction_va") for rule in resolved} != expected_unknowns:
        raise AssertionError(f"schema-two Linux site identity changed: {resolved}")

    v3_result = run([
        str(arguments.checker), "--policy", str(LINUX_POLICY_V3),
        str(arguments.linux_image),
    ], expect=1)
    v3 = json.loads(v3_result.stdout)
    v3_coverage = v3.get("coverage")
    expected_v3_coverage = {
        "bytes": 119746,
        "call_depth_limit": 128,
        "calls": 1605,
        "function_limit": 4096,
        "indirect_target_edges": 22,
        "instructions": 43315,
        "max_call_depth_reached": 14,
        "policy_resolved_indirect_calls": 4,
        "regions": 563,
        "resolved_calls": 1542,
        "root_regions": 3,
        "transitive_functions": 560,
        "unknown_calls": 63,
    }
    if v3.get("result") != "FAIL" or v3_coverage != expected_v3_coverage:
        raise AssertionError(f"schema-three Linux discovery changed: {v3}")
    v3_findings = v3.get("findings")
    if not isinstance(v3_findings, list) or not all(
            isinstance(finding.get("call_path"), list) and finding["call_path"]
            for finding in v3_findings):
        raise AssertionError(
            f"schema-three Linux findings lost call paths: {v3_findings}"
        )
    for finding in v3_findings:
        check_call_path(finding, finding["call_path"])
    v3_finding_counts = collections.Counter(
        finding.get("rule") for finding in v3_findings
    )
    expected_v3_findings = {
        "decode-failure": 9,
        "unknown-call": 63,
    }
    if v3_finding_counts != expected_v3_findings:
        raise AssertionError(
            f"schema-three Linux findings changed: {v3_finding_counts}"
        )
    v3_functions = v3.get("resolved_transitive_functions")
    if not isinstance(v3_functions, list) or len(v3_functions) != 560:
        raise AssertionError(
            f"schema-three Linux function set changed: {v3_functions}"
        )
    for function in v3_functions:
        check_call_path(function, function["call_path"])
    return {
        "schema_one": {
            "result": v1["result"],
            "coverage": v1_coverage,
            "findings": v1_findings,
        },
        "schema_two": {
            "result": v2["result"],
            "coverage": v2_coverage,
            "resolved_indirect_calls": resolved,
            "image": v2["image"],
        },
        "schema_three": {
            "result": v3["result"],
            "coverage": v3_coverage,
            "finding_counts": dict(sorted(v3_finding_counts.items())),
            "resolved_transitive_functions": len(v3_functions),
            "image": v3["image"],
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clang", required=True, type=pathlib.Path)
    parser.add_argument("--ld-lld", required=True, type=pathlib.Path)
    parser.add_argument("--checker", required=True, type=pathlib.Path)
    parser.add_argument("--linux-image", type=pathlib.Path)
    arguments = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="rv-entrycheck-") as temporary:
        root = pathlib.Path(temporary)
        objects = {}
        fixtures = (
            ("good", None, None),
            ("bad", "ENTRYCHECK_BAD", "forbidden-call"),
            ("unknown", "ENTRYCHECK_UNKNOWN", "unknown-call"),
            ("transitive-good", "ENTRYCHECK_TRANSITIVE_GOOD", None),
            ("transitive-bad", "ENTRYCHECK_TRANSITIVE_BAD", None),
            ("transitive-unknown", "ENTRYCHECK_TRANSITIVE_UNKNOWN", None),
            ("transitive-zero-size", "ENTRYCHECK_TRANSITIVE_ZERO_SIZE", None),
            ("transitive-cycle", "ENTRYCHECK_TRANSITIVE_CYCLE", None),
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
        indirect_receipts = check_indirect_policies(arguments, images, root)
        transitive_receipts = check_transitive_policies(arguments, images, root)
        linux_receipt = (check_linux_image(arguments)
                         if arguments.linux_image else "not-requested")

        print(json.dumps({
            "result": "PASS",
            "lanes": receipts,
            "invalid_policies": policy_receipts,
            "missing_boundary": boundary_receipt,
            "section_mode": section_receipts,
            "overlapping_regions": overlap_receipt,
            "invalid_images": invalid_image_receipts,
            "indirect_policies": indirect_receipts,
            "transitive_policies": transitive_receipts,
            "linux_image": linux_receipt,
        }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
