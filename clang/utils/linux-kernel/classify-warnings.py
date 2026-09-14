#!/usr/bin/env python3
"""Classify Clang Linux-kernel diagnostics by upstream source evolution."""

from __future__ import annotations

import argparse
import collections
import dataclasses
import posixpath
import pathlib
import re
import subprocess
import sys


WARNING_RE = re.compile(
    r"^(?P<file>.+?):(?P<line>\d+):(?P<column>\d+): warning: "
    r"(?P<message>.*?) "
    r"\[(?P<option>-W(?:linux-kernel(?:-[^]]+)?|conditional-uninitialized))\]$"
)


@dataclasses.dataclass(frozen=True)
class Warning:
    path: str
    line: int
    column: int
    message: str
    option: str


@dataclasses.dataclass(frozen=True)
class Evolution:
    status: str
    added: int = 0
    deleted: int = 0
    old_lines: int = 0


def git(repo: pathlib.Path, *args: str, check: bool = True) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=check,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return result.stdout


def parse_warnings(log: pathlib.Path, stable_tree: pathlib.Path) -> list[Warning]:
    root = str(stable_tree.resolve()) + "/"
    warnings: set[Warning] = set()
    with log.open(encoding="utf-8", errors="replace") as stream:
        for raw_line in stream:
            match = WARNING_RE.match(raw_line.rstrip("\n"))
            if not match:
                continue
            filename = match.group("file")
            if filename.startswith(root):
                filename = filename[len(root) :]
            elif pathlib.Path(filename).is_absolute():
                continue
            filename = posixpath.normpath(filename)
            if filename == ".." or filename.startswith("../"):
                continue
            warnings.add(
                Warning(
                    path=filename,
                    line=int(match.group("line")),
                    column=int(match.group("column")),
                    message=match.group("message"),
                    option=match.group("option"),
                )
            )
    return sorted(warnings, key=lambda item: (item.path, item.line, item.column))


def blob_line_count(repo: pathlib.Path, ref: str, path: str) -> int:
    output = git(repo, "show", f"{ref}:{path}", check=False)
    return output.count("\n") + bool(output and not output.endswith("\n"))


def classify_path(
    repo: pathlib.Path, stable_ref: str, mainline_ref: str, path: str
) -> Evolution:
    exists = subprocess.run(
        ["git", "-C", str(repo), "cat-file", "-e", f"{mainline_ref}:{path}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode == 0
    old_lines = blob_line_count(repo, stable_ref, path)
    if not exists:
        return Evolution("removed", deleted=old_lines, old_lines=old_lines)

    numstat = git(
        repo,
        "diff",
        "--no-renames",
        "--numstat",
        f"{stable_ref}..{mainline_ref}",
        "--",
        path,
    ).strip()
    if not numstat:
        return Evolution("unchanged", old_lines=old_lines)

    fields = numstat.split("\t", 2)
    if len(fields) < 2 or fields[0] == "-" or fields[1] == "-":
        return Evolution("rewritten", old_lines=old_lines)
    added, deleted = int(fields[0]), int(fields[1])
    churn = added + deleted
    threshold = max(100, old_lines // 2)
    status = "rewritten" if churn >= threshold else "changed"
    return Evolution(status, added=added, deleted=deleted, old_lines=old_lines)


def escape_table(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", required=True, type=pathlib.Path)
    parser.add_argument("--stable-tree", required=True, type=pathlib.Path)
    parser.add_argument("--git-repo", required=True, type=pathlib.Path)
    parser.add_argument("--stable-ref", required=True)
    parser.add_argument("--mainline-ref", required=True)
    parser.add_argument("--output", type=pathlib.Path)
    arguments = parser.parse_args()

    warnings = parse_warnings(arguments.log, arguments.stable_tree)
    paths = sorted({warning.path for warning in warnings})
    evolution = {
        path: classify_path(
            arguments.git_repo,
            arguments.stable_ref,
            arguments.mainline_ref,
            path,
        )
        for path in paths
    }

    counts = collections.Counter(evolution[warning.path].status for warning in warnings)
    rows = sorted(
        warnings,
        key=lambda warning: (
            {"removed": 0, "rewritten": 1, "changed": 2, "unchanged": 3}[
                evolution[warning.path].status
            ],
            warning.path,
            warning.line,
        ),
    )

    lines = [
        "# Linux kernel warning evolution report",
        "",
        f"Stable source: `{arguments.stable_ref}`  ",
        f"Comparison source: `{arguments.mainline_ref}`  ",
        f"Unique diagnostics: **{len(warnings)}**",
        "",
        "A file is marked `rewritten` when its line churn is at least 100 lines "
        "and at least half of its stable-version length. `removed` also includes "
        "files replaced under a new path.",
        "",
        "| Status | Diagnostics |",
        "| --- | ---: |",
    ]
    for status in ("removed", "rewritten", "changed", "unchanged"):
        lines.append(f"| {status} | {counts[status]} |")
    lines.extend(
        [
            "",
            "| Evolution | Location | Warning | Churn |",
            "| --- | --- | --- | ---: |",
        ]
    )
    for warning in rows:
        change = evolution[warning.path]
        churn = "removed" if change.status == "removed" else f"+{change.added}/-{change.deleted}"
        location = f"`{warning.path}:{warning.line}:{warning.column}`"
        message = escape_table(f"{warning.message} [{warning.option}]")
        lines.append(f"| {change.status} | {location} | {message} | {churn} |")
    output = "\n".join(lines) + "\n"

    if arguments.output:
        arguments.output.write_text(output, encoding="utf-8")
    else:
        sys.stdout.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
