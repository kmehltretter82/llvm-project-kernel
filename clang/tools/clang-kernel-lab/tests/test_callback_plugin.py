#!/usr/bin/env python3
"""Smoke-test the explicitly code-changing callback/perturb pass."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import tempfile


HERE = pathlib.Path(__file__).resolve().parent
TOOL = HERE.parent
SOURCE = HERE / "callback-probe.c"
SPEC = TOOL / "examples" / "riscv-callback-v1.json"


def compile_ir(clang: str, plugin: pathlib.Path, output: pathlib.Path,
               *, enabled: bool) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    if enabled:
        environment["CLANG_KERNEL_LAB_SPEC"] = str(SPEC)
    else:
        environment.pop("CLANG_KERNEL_LAB_SPEC", None)
    return subprocess.run(
        [
            clang,
            "--target=riscv64-unknown-elf",
            "-O1",
            "-g",
            "-S",
            "-emit-llvm",
            f"-fpass-plugin={plugin}",
            str(SOURCE),
            "-o",
            str(output),
        ],
        env=environment,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clang", required=True)
    parser.add_argument("--plugin", required=True, type=pathlib.Path)
    arguments = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="clang-kernel-lab-") as temporary:
        directory = pathlib.Path(temporary)
        enabled = compile_ir(
            arguments.clang, arguments.plugin, directory / "enabled.ll",
            enabled=True,
        )
        if enabled.returncode:
            raise RuntimeError(enabled.stderr)
        disabled = compile_ir(
            arguments.clang, arguments.plugin, directory / "disabled.ll",
            enabled=False,
        )
        if disabled.returncode:
            raise RuntimeError(disabled.stderr)

        instrumented = (directory / "enabled.ll").read_text(encoding="utf-8")
        control = (directory / "disabled.ll").read_text(encoding="utf-8")
        required = (
            "@__clang_kernel_lab_callback",
            "@__clang_kernel_lab_perturb",
            'section ".clang_kernel_lab.callback_sites"',
            "!clang.kernel.lab.callback_sites",
            '"clang.kernel.lab.instrumented"',
            '"clang.kernel.lab.spec_hash"',
        )
        for needle in required:
            if needle not in instrumented:
                raise AssertionError(f"instrumented IR lacks {needle!r}")
        for needle in required:
            if needle in control:
                raise AssertionError(f"disabled IR unexpectedly contains {needle!r}")

        callback_calls = instrumented.count(
            "call void @__clang_kernel_lab_callback"
        )
        perturb_calls = instrumented.count(
            "call void @__clang_kernel_lab_perturb"
        )
        if callback_calls < 4 or perturb_calls != 1:
            raise AssertionError(
                f"unexpected hook counts: callback={callback_calls}, "
                f"perturb={perturb_calls}"
            )
        print(json.dumps({
            "result": "PASS",
            "target": "riscv64-unknown-elf",
            "mode": "callback+perturb",
            "callback_calls": callback_calls,
            "perturb_calls": perturb_calls,
            "disabled_mode_hooks": 0,
        }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
