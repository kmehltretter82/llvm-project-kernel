#!/usr/bin/env python3
"""Check the Kernel Lab QEMU/Linux architecture inventory against source.

This is deliberately a source-only check.  It does not claim that a target
boots Linux or that its interrupt callback is semantically complete.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any


HOOK = "qemu_plugin_vcpu_interrupt_cb"


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
    if matrix.get("schema_version") != 1:
        errors.append("manifest schema_version is not 1")

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

    rows: list[tuple[str, str, str]] = []
    known_gaps = 0
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
            known_gaps += 1
            if has_hook:
                warnings.append(
                    f"{name}: interrupt hook now exists; update the manifest and plan"
                )
            hook_state = "KNOWN GAP" if not has_hook else "GAP CLOSED?"
        elif not has_hook:
            errors.append(f"{name}: expected interrupt hook is absent")
            hook_state = "MISSING"
        else:
            hook_state = "PRESENT"

        rows.append((name, family["linux_arch"], hook_state))

    if args.require_complete_hooks and known_gaps:
        errors.append(f"{known_gaps} known interrupt-hook gap(s) remain")

    if args.json:
        print(
            json.dumps(
                {
                    "families": [
                        {"name": name, "linux_arch": arch, "hook": hook}
                        for name, arch, hook in rows
                    ],
                    "errors": errors,
                    "warnings": warnings,
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print("family       linux arch   CPU interrupt hook")
        print("------------ ------------ ------------------")
        for name, arch, hook in rows:
            print(f"{name:12} {arch:12} {hook}")
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
        "--require-complete-hooks",
        action="store_true",
        help="fail for a source gap recorded as known-missing",
    )
    return parser.parse_args()


if __name__ == "__main__":
    sys.exit(check(parse_args()))
