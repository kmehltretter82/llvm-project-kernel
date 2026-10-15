#!/usr/bin/env python3
"""Check the Kernel Lab QEMU/Linux inventory and frozen contracts.

This is deliberately a source-only check of target coverage, compiler/QEMU
schedule vocabulary, replay documentation, and named source gaps.  It does not
claim that a target boots Linux or that an interrupt path is qualified.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import runpy
import subprocess
import sys
from typing import Any


HOOK = "qemu_plugin_vcpu_interrupt_cb"
SCHEDULE_CONTRACT = {
    "trigger_phase": "AFTER_PREVIOUS_RETIRE/BEFORE_INSN_AT_SITE",
    "hit_count_scopes": ["per-vcpu", "global"],
    "initial_hit_count_scope": "per-vcpu",
    "initial_operations": ["assert", "deassert", "pulse"],
    "direct_cpu_operation": "force-cpu-trap-test-only",
}
REQUIRED_CONTROLLER_GAPS = {"riscv-sifive-plic-level-lifecycle"}


def load_json(path: pathlib.Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def system_targets(qemu: pathlib.Path) -> set[str]:
    configs = qemu / "configs" / "targets"
    return {
        path.name.removesuffix("-softmmu.mak")
        for path in configs.glob("*-softmmu.mak")
    }


def linux_arches(linux: pathlib.Path) -> set[str]:
    return {
        path.name
        for path in (linux / "arch").iterdir()
        if path.is_dir()
    }


def git_head(tree: pathlib.Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(tree), "rev-parse", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode:
        detail = result.stderr.strip() or "git rev-parse failed"
        raise ValueError(detail)
    return result.stdout.strip()


def replay_platforms(qemu: pathlib.Path) -> set[str]:
    replay_doc = qemu / "docs/system/replay.rst"
    text = replay_doc.read_text(encoding="utf-8", errors="replace")
    match = re.search(
        r"^\s*\* Supports\s+(.*?)\s+hardware platforms\.",
        text,
        flags=re.MULTILINE | re.DOTALL,
    )
    if not match:
        raise ValueError("cannot find the supported-platform list in replay.rst")
    value = " ".join(match.group(1).split())
    value = value.replace(", and ", ", ").replace(" and ", ", ")
    return {item.strip() for item in value.split(",") if item.strip()}


def compiler_schedule_contract() -> tuple[str, str]:
    qemu_dir = pathlib.Path(__file__).resolve().parent
    site_format = qemu_dir.parent / "irq_site_format.py"
    values = runpy.run_path(str(site_format))
    trigger_phase = values.get("TRIGGER_PHASE")
    if not isinstance(trigger_phase, str):
        raise ValueError("irq_site_format.py has no textual TRIGGER_PHASE")

    site_tool = (
        qemu_dir.parents[2]
        / "tools/clang-kernel-lab/llvm-riscv-irq-sites.cpp"
    )
    text = site_tool.read_text(encoding="utf-8", errors="replace")
    match = re.search(
        r'\{\s*"default_hit_count_scope"\s*,\s*"([^"]+)"\s*\}', text
    )
    if not match:
        raise ValueError("site tool has no default_hit_count_scope field")
    return trigger_phase, match.group(1)


def format_set(values: set[str]) -> str:
    return ", ".join(sorted(values)) if values else "(none)"


def check(args: argparse.Namespace) -> int:
    matrix = load_json(args.matrix)
    qemu = args.qemu.resolve()
    linux = args.linux.resolve()
    errors: list[str] = []
    warnings: list[str] = []

    if not (qemu / "configs/targets").is_dir():
        print(f"error: not a QEMU source tree: {qemu}", file=sys.stderr)
        return 2
    if not (linux / "arch").is_dir():
        print(f"error: not a Linux source tree: {linux}", file=sys.stderr)
        return 2
    if args.verify_revisions:
        evidence = matrix.get("evidence")
        if not isinstance(evidence, dict):
            errors.append("manifest evidence must be an object")
        else:
            for label, tree, key in (
                ("QEMU", qemu, "qemu_commit"),
                ("Linux", linux, "linux_commit"),
            ):
                try:
                    observed = git_head(tree)
                except ValueError as error:
                    errors.append(f"cannot identify {label} revision: {error}")
                    continue
                expected = evidence.get(key)
                if observed != expected:
                    errors.append(
                        f"{label} revision differs: expected {expected}, "
                        f"observed {observed}"
                    )
    if matrix.get("schema_version") != 2:
        errors.append("manifest schema_version is not 2")

    schedule_contract = matrix.get("schedule_contract")
    if schedule_contract != SCHEDULE_CONTRACT:
        errors.append(
            "schedule contract differs from the version-two QEMU/LLVM contract"
        )
    try:
        compiler_phase, compiler_scope = compiler_schedule_contract()
    except (OSError, ValueError) as error:
        errors.append(f"cannot inspect the compiler site contract: {error}")
    else:
        if not isinstance(schedule_contract, dict):
            errors.append("schedule_contract must be an object")
        else:
            if schedule_contract.get("trigger_phase") != compiler_phase:
                errors.append("QEMU and compiler trigger phases differ")
            if schedule_contract.get("initial_hit_count_scope") != compiler_scope:
                errors.append("QEMU and sidecar hit-count scopes differ")

    families = matrix.get("families", [])
    if len(families) != 17:
        errors.append(f"manifest has {len(families)} families, expected 17")

    names = [family["name"] for family in families]
    if len(names) != len(set(names)):
        errors.append("family names are not unique")

    linux_names = [family["linux_arch"] for family in families]
    if len(linux_names) != len(set(linux_names)):
        errors.append("Linux architecture mappings are not unique")

    excluded = matrix["excluded"]
    declared_qemu = {
        target
        for family in families
        for target in family["qemu_system_targets"]
    }
    declared_qemu.update(excluded["qemu_system_targets_without_linux_arch"])
    actual_qemu = system_targets(qemu)
    if declared_qemu != actual_qemu:
        errors.append(
            "QEMU system-target inventory differs: "
            f"undeclared={format_set(actual_qemu - declared_qemu)}; "
            f"stale={format_set(declared_qemu - actual_qemu)}"
        )

    declared_linux = set(linux_names)
    declared_linux.update(excluded["linux_arches_without_qemu_system_target"])
    actual_linux = linux_arches(linux)
    if declared_linux != actual_linux:
        errors.append(
            "Linux architecture inventory differs: "
            f"undeclared={format_set(actual_linux - declared_linux)}; "
            f"stale={format_set(declared_linux - actual_linux)}"
        )

    try:
        documented_replay = replay_platforms(qemu)
    except (OSError, ValueError) as error:
        documented_replay = set()
        errors.append(f"cannot inspect QEMU replay support: {error}")

    controller_gaps = matrix.get("known_controller_gaps")
    if not isinstance(controller_gaps, list):
        controller_gaps = []
        errors.append("known_controller_gaps must be an array")
    gap_ids: set[str] = set()
    open_controller_gaps = 0
    family_names = set(names)
    for gap in controller_gaps:
        if not isinstance(gap, dict):
            errors.append("controller-gap entries must be objects")
            continue
        gap_id = gap.get("id")
        family = gap.get("family")
        status = gap.get("status")
        relative = gap.get("source_file")
        evidence = gap.get("source_evidence")
        if not isinstance(gap_id, str) or not gap_id:
            errors.append("controller gap has an invalid id")
            continue
        if gap_id in gap_ids:
            errors.append(f"duplicate controller gap id: {gap_id}")
        gap_ids.add(gap_id)
        if family not in family_names:
            errors.append(f"{gap_id}: unknown family {family!r}")
        if status not in {"open", "closed"}:
            errors.append(f"{gap_id}: status must be 'open' or 'closed'")
        elif status == "open":
            open_controller_gaps += 1
        else:
            closure = gap.get("closure_evidence")
            if not isinstance(closure, list) or not closure or not all(
                isinstance(item, str) and item for item in closure
            ):
                errors.append(
                    f"{gap_id}: a closed gap requires named closure_evidence"
                )
        acceptance = gap.get("acceptance")
        if not isinstance(acceptance, str) or not acceptance:
            errors.append(f"{gap_id}: acceptance must be a nonempty string")
        if not isinstance(relative, str) or not relative:
            errors.append(f"{gap_id}: source_file must be a nonempty string")
            continue
        source = qemu / relative
        if not source.is_file():
            errors.append(f"{gap_id}: missing source file: {relative}")
            continue
        if not isinstance(evidence, list) or not evidence or not all(
            isinstance(item, str) and item for item in evidence
        ):
            errors.append(f"{gap_id}: source_evidence must be nonempty strings")
            continue
        source_text = source.read_text(encoding="utf-8", errors="replace")
        missing_evidence = [item for item in evidence if item not in source_text]
        if missing_evidence:
            errors.append(
                f"{gap_id}: source changed; re-audit missing evidence: "
                + ", ".join(repr(item) for item in missing_evidence)
            )
    missing_required_gaps = REQUIRED_CONTROLLER_GAPS - gap_ids
    if missing_required_gaps:
        errors.append(
            "required controller gaps are absent: "
            + format_set(missing_required_gaps)
        )

    rows: list[tuple[str, str, str, str]] = []
    known_gaps = 0
    classification_audits = 0
    replay_qualification = 0
    for family in families:
        name = family["name"]
        expectation = family["interrupt_hook"]
        if expectation not in {
            "present",
            "known-missing",
            "present-needs-classification-audit",
        }:
            errors.append(f"{name}: unknown interrupt_hook state {expectation!r}")
            continue

        missing_files = []
        hook_files = []
        for relative in family["entry_files"]:
            path = qemu / relative
            if not path.is_file():
                missing_files.append(relative)
                continue
            if HOOK in path.read_text(encoding="utf-8", errors="replace"):
                hook_files.append(relative)

        for relative in family["controller_files"]:
            if not (qemu / relative).is_file():
                missing_files.append(relative)

        if missing_files:
            errors.append(f"{name}: missing source files: {', '.join(missing_files)}")

        has_hook = bool(hook_files)
        if expectation == "known-missing":
            if has_hook:
                errors.append(
                    f"{name}: interrupt hook now exists; update the manifest and plan"
                )
            else:
                known_gaps += 1
            hook_state = "KNOWN GAP" if not has_hook else "GAP CLOSED?"
        elif not has_hook:
            errors.append(f"{name}: expected interrupt hook is absent")
            hook_state = "MISSING"
        elif expectation == "present-needs-classification-audit":
            classification_audits += 1
            hook_state = "AUDIT REQUIRED"
        else:
            hook_state = "PRESENT"

        replay_names = family.get("replay_doc_names")
        replay_status = family.get("replay_status")
        if not isinstance(replay_names, list) or not replay_names or not all(
            isinstance(item, str) and item for item in replay_names
        ):
            errors.append(f"{name}: replay_doc_names must be nonempty strings")
            replay_names = []
        if replay_status not in {"documented", "qualification-required"}:
            errors.append(f"{name}: unknown replay_status {replay_status!r}")
            replay_state = "INVALID"
        else:
            present_names = set(replay_names) & documented_replay
            if replay_status == "documented":
                missing_names = set(replay_names) - documented_replay
                if missing_names:
                    errors.append(
                        f"{name}: replay documentation names are absent: "
                        f"{format_set(missing_names)}"
                    )
                replay_state = "DOCUMENTED"
            else:
                replay_qualification += 1
                if present_names:
                    errors.append(
                        f"{name}: replay documentation now names "
                        f"{format_set(present_names)}; update its status"
                    )
                replay_state = "QUALIFY"

        rows.append((name, family["linux_arch"], hook_state, replay_state))

    if args.require_complete_hooks and known_gaps and not args.require_qualified:
        errors.append(f"{known_gaps} known interrupt-hook gap(s) remain")
    if args.require_qualified:
        if known_gaps:
            errors.append(f"{known_gaps} known interrupt-hook gap(s) remain")
        if classification_audits:
            errors.append(
                f"{classification_audits} interrupt classification audit(s) remain"
            )
        if replay_qualification:
            errors.append(
                f"{replay_qualification} replay qualification gap(s) remain"
            )
        if open_controller_gaps:
            errors.append(
                f"{open_controller_gaps} controller lifecycle gap(s) remain"
            )

    if args.json:
        print(
            json.dumps(
                {
                    "families": [
                        {
                            "name": name,
                            "linux_arch": arch,
                            "hook": hook,
                            "replay": replay,
                        }
                        for name, arch, hook, replay in rows
                    ],
                    "open_controller_gaps": open_controller_gaps,
                    "errors": errors,
                    "warnings": warnings,
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print("family       linux arch   CPU interrupt hook replay")
        print("------------ ------------ ------------------ ----------")
        for name, arch, hook, replay in rows:
            print(f"{name:12} {arch:12} {hook:18} {replay}")
        print(f"open controller lifecycle gaps: {open_controller_gaps}")
        for warning in warnings:
            print(f"warning: {warning}", file=sys.stderr)
        for error in errors:
            print(f"error: {error}", file=sys.stderr)

    return 1 if errors else 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--qemu", required=True, type=pathlib.Path)
    parser.add_argument("--linux", required=True, type=pathlib.Path)
    parser.add_argument(
        "--matrix",
        type=pathlib.Path,
        default=pathlib.Path(__file__).with_name("architecture-matrix.json"),
    )
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--verify-revisions",
        action="store_true",
        help="require the QEMU and Linux HEADs recorded by the manifest",
    )
    parser.add_argument(
        "--require-complete-hooks",
        action="store_true",
        help="fail for a source gap recorded as known-missing",
    )
    parser.add_argument(
        "--require-qualified",
        action="store_true",
        help="fail for every known hook, classification, replay, or controller gap",
    )
    return parser.parse_args()


if __name__ == "__main__":
    sys.exit(check(parse_args()))
