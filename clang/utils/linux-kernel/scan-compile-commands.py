#!/usr/bin/env python3
"""Run Linux-kernel warnings over entries in a compilation database."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import pathlib
import shlex
import subprocess
import sys


def command_arguments(entry: dict[str, object]) -> list[str]:
    arguments = entry.get("arguments")
    if isinstance(arguments, list):
        return [str(argument) for argument in arguments]
    command = entry.get("command")
    if isinstance(command, str):
        return shlex.split(command)
    raise ValueError("compilation database entry has no command")


def scan_arguments(
    arguments: list[str], clang: pathlib.Path, analyze: bool
) -> list[str]:
    result = [str(clang)]
    skip_next = False
    options_with_value = {"-MF", "-MT", "-MQ", "-o"}
    for argument in arguments[1:]:
        if skip_next:
            skip_next = False
            continue
        if argument in options_with_value:
            skip_next = True
            continue
        if argument == "-c" or argument in {"-MD", "-MMD"}:
            continue
        if argument.startswith("-Wp,-MD,") or argument.startswith("-Wp,-MMD,"):
            continue
        result.append(argument)
    result.append("--analyze" if analyze else "-fsyntax-only")
    return result


def relative_source(entry: dict[str, object], source_root: pathlib.Path) -> str:
    source = pathlib.Path(str(entry["file"])).resolve()
    try:
        return source.relative_to(source_root.resolve()).as_posix()
    except ValueError:
        return source.as_posix()


def run_entry(
    index: int,
    entry: dict[str, object],
    clang: pathlib.Path,
    extra_arguments: list[str],
    analyze: bool,
) -> tuple[int, str, int, str]:
    arguments = scan_arguments(command_arguments(entry), clang, analyze)
    arguments.extend(extra_arguments)
    try:
        result = subprocess.run(
            arguments,
            cwd=str(entry["directory"]),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
        )
    except OSError as error:
        return (
            index,
            str(entry["file"]),
            127,
            f"failed to launch compiler: {error}\n",
        )
    return index, str(entry["file"]), result.returncode, result.stdout


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", required=True, type=pathlib.Path)
    parser.add_argument("--source-root", required=True, type=pathlib.Path)
    parser.add_argument("--clang", required=True, type=pathlib.Path)
    parser.add_argument("--path-prefix", action="append", default=[])
    parser.add_argument("--extra-arg", action="append", default=[])
    parser.add_argument("--analyze", action="store_true")
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--output", type=pathlib.Path)
    arguments = parser.parse_args()

    with arguments.database.open(encoding="utf-8") as stream:
        database = json.load(stream)

    clang = arguments.clang.resolve()
    selected = []
    for entry in database:
        source = relative_source(entry, arguments.source_root)
        if not source.endswith(".c"):
            continue
        if arguments.path_prefix and not any(
            source.startswith(prefix) for prefix in arguments.path_prefix
        ):
            continue
        selected.append(entry)

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=arguments.jobs) as pool:
        futures = [
            pool.submit(
                run_entry,
                index,
                entry,
                clang,
                arguments.extra_arg,
                arguments.analyze,
            )
            for index, entry in enumerate(selected)
        ]
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())

    failed = 0
    lines = []
    for _, source, returncode, output in sorted(results):
        if output:
            lines.append(output.rstrip())
        if returncode:
            failed += 1
            lines.append(f"{source}: compiler exited with status {returncode}")
    lines.append(f"Scanned {len(selected)} translation units; {failed} failed.")
    report = "\n".join(lines) + "\n"

    if arguments.output:
        arguments.output.write_text(report, encoding="utf-8")
    else:
        sys.stdout.write(report)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
