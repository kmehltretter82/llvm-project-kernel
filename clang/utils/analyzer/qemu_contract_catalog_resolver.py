#!/usr/bin/env python3
"""Resolve QEMU analyzer contracts against an exact compilation database.

The resolver replays the unique C-family Clang command for each catalog-declared
translation-unit anchor in syntax-only AST dump mode.  Catalog selectors are
matched by function name, declaration header, and global declaration identity,
and member paths are matched against complete global record definitions and
exact field types, so unrelated declarations cannot satisfy a contract.
Callback slots are tied to exact implementations through an attested
TypeInfo.class_init variable initializer, class-initializer definition, and
lexical slot assignment in separately declared translation-unit anchors.  The resulting
JSON report is deliberately free of timestamps and AST node IDs and is stable
for the same catalog, sources, and compilation database.  This verifies source
drift within the supplied anchors; campaign coverage must separately attest
that the database is complete.
"""

import argparse
import hashlib
import json
import os
import re
import selectors
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from pathlib import Path

import qemu_contract_catalog as catalog_tool


REPORT_FORMAT = 2
DEFAULT_TIMEOUT_SECONDS = 120
MAX_ANCHOR_COMMANDS = 32
MAX_AST_RUNS = 64
MAX_AST_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_DIAGNOSTIC_BYTES = 1024 * 1024
MAX_COMPILE_DATABASE_BYTES = 64 * 1024 * 1024
MAX_COMPILE_COMMANDS = 65536
MAX_DEPENDENCY_FILE_BYTES = 8 * 1024 * 1024
MAX_DEPENDENCIES = 65536
MAX_ATTESTED_FILE_BYTES = 512 * 1024 * 1024
MAX_AGGREGATE_ATTESTED_BYTES = 2 * 1024 * 1024 * 1024
_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_C_FAMILY_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".c++", ".C", ".m", ".mm"}
_C_FAMILY_LANGUAGES = {
    "c",
    "c-header",
    "cpp-output",
    "c++",
    "c++-header",
    "c++-cpp-output",
    "objective-c",
    "objective-c-header",
    "objective-c++",
    "objective-c++-header",
}
_SEMANTIC_ENVIRONMENT = (
    "C_INCLUDE_PATH",
    "CPLUS_INCLUDE_PATH",
    "CPATH",
    "DEVELOPER_DIR",
    "MACOSX_DEPLOYMENT_TARGET",
    "OBJC_INCLUDE_PATH",
    "PATH",
    "SDKROOT",
)
_REJECTED_DRIVER_OPTIONS = (
    "--config",
    "--config-system-dir",
    "--config-user-dir",
)
_REJECTED_SEMANTIC_AUXILIARY_OPTIONS = {
    "-add-plugin",
    "-ast-merge",
    "-chain-include",
    "-fapinotes",
    "-fapinotes-modules",
    "-fcas-fs",
    "-fcas-fs-working-directory",
    "-fcas-include-tree",
    "-fcas-path",
    "-fcas-plugin-option",
    "-fcas-plugin-path",
    "-fprebuilt-module-path",
    "-iapinotes-modules",
    "-iapinotes-path",
    "-include-pch",
    "-include-pth",
    "-ivfsstatcache",
    "-ivfsoverlay",
    "-load",
    "-load-pass-plugin",
    "-multi-lib-config",
    "-plugin",
    "-remap-file",
    "-vfsoverlay",
}
_REJECTED_SEMANTIC_AUXILIARY_PREFIXES = (
    "-add-plugin=",
    "-ast-merge=",
    "-chain-include=",
    "-fapinotes-swift-version=",
    "-fcas-fs=",
    "-fcas-fs-working-directory=",
    "-fcas-include-tree=",
    "-fcas-path=",
    "-fcas-plugin-option=",
    "-fcas-plugin-path=",
    "-fmodule",
    "-fpass-plugin",
    "-fplugin",
    "-fprebuilt-module-path=",
    "-iapinotes-modules=",
    "-iapinotes-path=",
    "-include-pch=",
    "-include-pth=",
    "-ivfsstatcache=",
    "-ivfsoverlay=",
    "-load=",
    "-load-pass-plugin=",
    "-multi-lib-config=",
    "-pch-",
    "-plugin=",
    "-plugin-arg-",
    "-remap-file=",
    "-vfsoverlay=",
)


class ResolverError(ValueError):
    """A fail-closed compilation-database or AST resolution error."""


class _DeadlineExceeded(ResolverError):
    """The resolver's global wall-clock deadline has expired."""


def _check_deadline(deadline):
    if deadline is not None and time.monotonic() >= deadline:
        raise _DeadlineExceeded(
            "source-drift resolution exceeded its global deadline"
        )


class _AttestationBudget:
    """Bound the unique file content admitted to the attested input closure."""

    def __init__(self, limit, deadline):
        self.limit = limit
        self.deadline = deadline
        self.total = 0
        self._sizes = {}

    def reserve(self, path, size):
        _check_deadline(self.deadline)
        key = Path(path).resolve()
        previous = self._sizes.get(key, 0)
        if size <= previous:
            return
        total = self.total + size - previous
        if total > self.limit:
            raise ResolverError(
                "attested inputs exceed the {}-byte aggregate limit".format(
                    self.limit
                )
            )
        self._sizes[key] = size
        self.total = total


def _sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def _size_limit_error(path, maximum_bytes, limit_name=None):
    if limit_name is not None:
        return "{} exceeds the {}-byte limit".format(limit_name, maximum_bytes)
    return "{} exceeds the {}-byte attested-file limit".format(
        path, maximum_bytes
    )


def _sha256_file(path, budget=None, deadline=None,
                 maximum_bytes=MAX_ATTESTED_FILE_BYTES, limit_name=None):
    try:
        digest = hashlib.sha256()
        consumed = 0
        with Path(path).open("rb") as stream:
            while True:
                _check_deadline(deadline)
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                consumed += len(chunk)
                if consumed > maximum_bytes:
                    raise ResolverError(
                        _size_limit_error(path, maximum_bytes, limit_name)
                    )
                if budget is not None:
                    budget.reserve(path, consumed)
                digest.update(chunk)
        return digest.hexdigest()
    except OSError as error:
        raise ResolverError("{}: {}".format(path, error)) from error


def _file_snapshot(path, with_hash=False, budget=None, deadline=None,
                   maximum_bytes=MAX_ATTESTED_FILE_BYTES, limit_name=None):
    path = Path(path)
    _check_deadline(deadline)
    try:
        stat = path.stat()
    except OSError as error:
        raise ResolverError("{}: {}".format(path, error)) from error
    if stat.st_size > maximum_bytes:
        raise ResolverError(
            _size_limit_error(path, maximum_bytes, limit_name)
        )
    if budget is not None:
        budget.reserve(path, stat.st_size)
    snapshot = {"bytes": stat.st_size, "mtime_ns": stat.st_mtime_ns}
    if with_hash:
        snapshot["sha256"] = _sha256_file(
            path,
            budget=budget,
            deadline=deadline,
            maximum_bytes=maximum_bytes,
            limit_name=limit_name,
        )
    return snapshot


def _canonical_json(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _value_hash(value):
    return _sha256_bytes((_canonical_json(value) + "\n").encode("utf-8"))


def _resolve_path(value, base):
    path = Path(value)
    if not path.is_absolute():
        path = Path(base) / path
    return path.resolve()


def _display_path(path, source_root, database_root):
    path = Path(path).resolve()
    try:
        return "$SOURCE_ROOT/" + path.relative_to(source_root).as_posix()
    except ValueError:
        pass
    try:
        return "$COMPILE_DATABASE_DIR/" + path.relative_to(database_root).as_posix()
    except ValueError:
        return path.as_posix()


def _normalize_diagnostic(text, source_root, database_root):
    text = _ANSI_ESCAPE_RE.sub("", text or "").replace("\r\n", "\n")
    replacements = sorted(
        (
            (str(source_root), "$SOURCE_ROOT"),
            (str(database_root), "$COMPILE_DATABASE_DIR"),
        ),
        key=lambda item: len(item[0]),
        reverse=True,
    )
    for old, new in replacements:
        text = text.replace(old, new)
    return text.rstrip()


def _normalize_argument(argument, source_root, database_root):
    replacements = sorted(
        (
            (str(source_root), "$SOURCE_ROOT"),
            (str(database_root), "$COMPILE_DATABASE_DIR"),
        ),
        key=lambda item: len(item[0]),
        reverse=True,
    )
    for old, new in replacements:
        argument = argument.replace(old, new)
    return argument


def _load_compile_commands(path, source_root, deadline=None):
    _check_deadline(deadline)
    try:
        database_bytes = Path(path).stat().st_size
    except OSError as error:
        raise ResolverError("{}: {}".format(path, error)) from error
    if database_bytes > MAX_COMPILE_DATABASE_BYTES:
        raise ResolverError(
            "compile_commands.json exceeds the {}-byte limit".format(
                MAX_COMPILE_DATABASE_BYTES
            )
        )
    commands = catalog_tool.load_json_strict(path)
    if not isinstance(commands, list) or not commands:
        raise ResolverError("compile_commands.json must be a non-empty array")
    if len(commands) > MAX_COMPILE_COMMANDS:
        raise ResolverError(
            "compile_commands.json has {} entries; limit is {}".format(
                len(commands), MAX_COMPILE_COMMANDS
            )
        )

    database_root = Path(path).resolve().parent
    normalized = []
    for index, entry in enumerate(commands):
        _check_deadline(deadline)
        where = "compile_commands[{}]".format(index)
        if not isinstance(entry, dict):
            raise ResolverError("{} must be an object".format(where))
        unknown = sorted(set(entry) - {"directory", "file", "arguments", "command", "output"})
        if unknown:
            raise ResolverError(
                "{} has unknown field(s): {}".format(where, ", ".join(unknown))
            )
        if not isinstance(entry.get("directory"), str) or not entry["directory"]:
            raise ResolverError("{}.directory must be a non-empty string".format(where))
        if not isinstance(entry.get("file"), str) or not entry["file"]:
            raise ResolverError("{}.file must be a non-empty string".format(where))
        has_arguments = "arguments" in entry
        has_command = "command" in entry
        if has_arguments == has_command:
            raise ResolverError(
                "{} must contain exactly one of arguments or command".format(where)
            )
        if has_arguments:
            arguments = entry["arguments"]
            if (
                not isinstance(arguments, list)
                or not arguments
                or any(not isinstance(argument, str) or not argument for argument in arguments)
            ):
                raise ResolverError(
                    "{}.arguments must be a non-empty string array".format(where)
                )
            arguments = list(arguments)
        else:
            if not isinstance(entry["command"], str) or not entry["command"]:
                raise ResolverError("{}.command must be a non-empty string".format(where))
            try:
                arguments = shlex.split(entry["command"], posix=True)
            except ValueError as error:
                raise ResolverError("{} has invalid shell quoting: {}".format(where, error))
            if not arguments:
                raise ResolverError("{}.command is empty after parsing".format(where))

        directory = _resolve_path(entry["directory"], database_root)
        source = _resolve_path(entry["file"], directory)
        identity = {
            "directory": _display_path(directory, source_root, database_root),
            "file": _display_path(source, source_root, database_root),
            "arguments": [
                _normalize_argument(argument, source_root, database_root)
                for argument in arguments
            ],
        }
        command_id = _value_hash(identity)
        normalized.append(
            {
                "id": command_id,
                "directory": directory,
                "file": source,
                "arguments": arguments,
                "identity": identity,
            }
        )

    by_id = {}
    for command in normalized:
        previous = by_id.get(command["id"])
        if previous is not None:
            if previous["identity"] != command["identity"]:
                raise ResolverError("compilation-command SHA-256 collision")
            continue
        by_id[command["id"]] = command
    return sorted(
        by_id.values(),
        key=lambda command: (
            command["file"].as_posix(),
            command["directory"].as_posix(),
            command["id"],
        ),
    ), len(commands)


def _is_semantic_auxiliary_option(argument):
    semantic_argument = argument
    if semantic_argument.startswith("-Xclang="):
        semantic_argument = semantic_argument[len("-Xclang=") :]
    return (
        semantic_argument in _REJECTED_SEMANTIC_AUXILIARY_OPTIONS
        or any(
            semantic_argument.startswith(prefix)
            for prefix in _REJECTED_SEMANTIC_AUXILIARY_PREFIXES
        )
    )


def _validate_driver_command_shape(command):
    arguments = command["arguments"]
    if any(argument.startswith("@") for argument in arguments[1:]):
        raise ResolverError(
            "anchor compile command uses a response file; exact expansion is required"
        )
    if "-cc1" in arguments[1:]:
        raise ResolverError(
            "anchor compile command invokes clang -cc1 directly; a driver is required"
        )
    if "-" in arguments[1:]:
        raise ResolverError("anchor compile command contains an additional stdin input")
    if "--" in arguments[1:]:
        raise ResolverError(
            "anchor compile command uses -- option termination; exact expansion is required"
        )
    for argument in arguments[1:]:
        for option in _REJECTED_DRIVER_OPTIONS:
            if argument == option or argument.startswith(option + "="):
                raise ResolverError(
                    "anchor compile command uses unsupported Clang configuration "
                    "option: {}".format(argument)
                )
        if _is_semantic_auxiliary_option(argument):
            raise ResolverError(
                "anchor compile command uses unsupported semantic auxiliary "
                "input option: {}".format(argument)
            )


def _controlled_environment(source_root, database_root):
    environment = {
        name: os.environ[name]
        for name in _SEMANTIC_ENVIRONMENT
        if name in os.environ
    }
    path = environment.get("PATH")
    if path is not None:
        components = path.split(os.pathsep)
        if any(not component or not Path(component).is_absolute()
               for component in components):
            raise ResolverError(
                "PATH must contain only non-empty absolute directories"
            )
    environment["LC_ALL"] = "C"
    environment["LANG"] = "C"
    semantic = {
        name: _normalize_argument(value, source_root, database_root)
        for name, value in sorted(environment.items())
    }
    return environment, semantic


class _OutputLimitExceeded(Exception):
    def __init__(self, stream, limit):
        super().__init__(stream)
        self.stream = stream
        self.limit = limit


def _terminate_process(process, process_group):
    # start_new_session=True gives this owned child a fresh process group.  The
    # leader may have already exited while a descendant still holds a pipe, so
    # signal the captured group even when process.poll() is no longer None.
    try:
        os.killpg(process_group, signal.SIGTERM)
    except OSError:
        if process.poll() is None:
            try:
                process.terminate()
            except OSError:
                pass
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process_group, signal.SIGKILL)
    except OSError:
        if process.poll() is None:
            try:
                process.kill()
            except OSError:
                pass
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        # The process is an owned child, but a platform-level refusal to kill
        # it must not replace the original timeout/output-limit result.
        pass


def _run_bounded(arguments, cwd, environment, timeout_seconds,
                 stdout_limit, stderr_limit):
    try:
        process = subprocess.Popen(
            arguments,
            cwd=cwd,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError:
        raise

    process_group = process.pid

    selector = selectors.DefaultSelector()
    streams = {
        process.stdout: ("stdout", bytearray(), stdout_limit),
        process.stderr: ("stderr", bytearray(), stderr_limit),
    }
    for stream in streams:
        selector.register(stream, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout_seconds
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _terminate_process(process, process_group)
                raise subprocess.TimeoutExpired(arguments, timeout_seconds)
            events = selector.select(min(remaining, 0.25))
            if not events:
                continue
            for key, _events in events:
                stream = key.fileobj
                chunk = os.read(stream.fileno(), 65536)
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                name, buffer, limit = streams[stream]
                buffer.extend(chunk)
                if len(buffer) > limit:
                    _terminate_process(process, process_group)
                    raise _OutputLimitExceeded(name, limit)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _terminate_process(process, process_group)
            raise subprocess.TimeoutExpired(arguments, timeout_seconds)
        returncode = process.wait(timeout=remaining)
    except BaseException:
        _terminate_process(process, process_group)
        raise
    finally:
        selector.close()
        for stream in streams:
            if not stream.closed:
                stream.close()
    return subprocess.CompletedProcess(
        arguments,
        returncode,
        bytes(streams[process.stdout][1]).decode("utf-8", errors="replace"),
        bytes(streams[process.stderr][1]).decode("utf-8", errors="replace"),
    )


def _resolve_executable(value, directory, environment, description):
    executable_path = Path(value)
    if executable_path.is_absolute():
        invocation = executable_path.absolute()
    elif os.path.sep in value or (
        os.path.altsep is not None and os.path.altsep in value
    ):
        invocation = _resolve_path(executable_path, directory)
    else:
        resolved = shutil.which(value, path=environment.get("PATH"))
        if resolved is None:
            raise ResolverError(
                "{} is not found on PATH: {}".format(description, value)
            )
        invocation = Path(resolved).absolute()
    if not invocation.is_file() or not os.access(invocation, os.X_OK):
        raise ResolverError("{} is not executable: {}".format(description, invocation))
    return invocation


def _resolve_compiler(command, source_root, database_root, environment,
                      remaining_seconds, budget=None, deadline=None):
    compiler = command["arguments"][0]
    invocation = _resolve_executable(
        compiler, command["directory"], environment, "anchor compiler"
    )

    compiler_target = invocation.resolve()
    invocation_snapshot = _file_snapshot(
        invocation, with_hash=True, budget=budget, deadline=deadline
    )
    snapshot = _file_snapshot(
        compiler_target, with_hash=True, budget=budget, deadline=deadline
    )
    timeout = min(10, remaining_seconds)
    if timeout <= 0:
        raise ResolverError("source-drift resolution exceeded its global deadline")
    try:
        version = _run_bounded(
            [str(invocation), "--no-default-config", "--version"],
            command["directory"],
            environment,
            timeout,
            MAX_DIAGNOSTIC_BYTES,
            MAX_DIAGNOSTIC_BYTES,
        )
    except (OSError, subprocess.TimeoutExpired, _OutputLimitExceeded) as error:
        raise ResolverError("cannot attest anchor compiler: {}".format(error)) from error
    version_text = (version.stdout + version.stderr).strip()
    if version.returncode != 0 or "clang" not in version_text.lower():
        raise ResolverError("anchor compiler is not a Clang driver")
    command["arguments"] = [str(invocation)] + command["arguments"][1:]
    command["compiler_invocation"] = invocation
    command["compiler_invocation_snapshot"] = invocation_snapshot
    command["compiler_target"] = compiler_target
    command["compiler_snapshot"] = snapshot
    command["compiler"] = {
        "requested": compiler,
        "invocation": _display_path(invocation, source_root, database_root),
        "resolved": _display_path(compiler_target, source_root, database_root),
        "bytes": snapshot["bytes"],
        "sha256": snapshot["sha256"],
        "version": _normalize_diagnostic(version_text, source_root, database_root),
    }
    return invocation


_OPTIONS_WITH_VALUE = {
    "-o",
    "-MF",
    "-MT",
    "-MQ",
    "-MJ",
    "--serialize-diagnostics",
    "-dependency-file",
}
_DROP_OPTIONS = {
    "-c",
    "-S",
    "-E",
    "-M",
    "-MM",
    "-MD",
    "-MMD",
    "-MP",
    "-MG",
    "-emit-ast",
    "-emit-llvm",
    "-save-temps",
    "--save-temps",
    "-ftime-trace",
    "-fsyntax-only",
}
_JOINED_DROP_PREFIXES = (
    "-MF",
    "-MT",
    "-MQ",
    "-MJ",
    "--serialize-diagnostics=",
    "-dependency-file=",
    "-save-temps=",
    "--save-temps=",
    "-ftime-trace=",
    "-Wp,-MD,",
    "-Wp,-MMD,",
)


def _sanitized_driver_command(arguments):
    result = [arguments[0], "--no-default-config"]
    index = 1
    while index < len(arguments):
        argument = arguments[index]
        if argument in _OPTIONS_WITH_VALUE:
            if index + 1 >= len(arguments):
                raise ResolverError("compile command ends after {}".format(argument))
            index += 2
            continue
        if argument in _DROP_OPTIONS:
            index += 1
            continue
        if argument == "--no-default-config":
            index += 1
            continue
        if argument == "-Xclang" and index + 1 < len(arguments):
            forwarded = arguments[index + 1]
            if forwarded in {"-ast-dump=json", "-ast-list"} or forwarded.startswith(
                "-ast-dump-filter="
            ):
                index += 2
                continue
        if any(argument.startswith(prefix) for prefix in _JOINED_DROP_PREFIXES):
            index += 1
            continue
        result.append(argument)
        index += 1
    return result


def _driver_plan_command(arguments):
    result = _sanitized_driver_command(arguments)
    result.extend(
        ["-fsyntax-only", "-Wno-unused-command-line-argument", "-###"]
    )
    return result


_CC1_REPLAY_CONTROL_OPTIONS = {
    "-dependency-file",
    "-header-include-file",
    "-module-file-deps",
    "-MT",
    "-o",
    "-show-includes",
    "-skip-unused-modulemap-deps",
    "-sys-header-deps",
}
_CC1_REPLAY_CONTROL_PREFIXES = (
    "-ast-",
    "-dependency-file=",
    "-header-include-",
    "-MT=",
    "-o=",
)
_CC1_INCOMPATIBLE_ACTIONS = {
    "-analyze",
    "-Eonly",
    "-fixit",
    "-fixit-recompile",
    "-migrate",
    "-module-file-info",
    "-rewrite-legacy-objc",
    "-rewrite-objc",
    "-verify-pch",
}


def _validate_cc1_replay_plan(cc1):
    """Require a side-effect-free base plan that can be replayed directly."""
    if cc1.count("-fsyntax-only") != 1:
        raise ResolverError(
            "Clang -cc1 plan is not an exact syntax-only replay plan"
        )
    for argument in cc1[1:]:
        if (
            argument in _CC1_REPLAY_CONTROL_OPTIONS
            or argument in _CC1_INCOMPATIBLE_ACTIONS
            or argument.startswith("-emit-")
            or any(
                argument.startswith(prefix)
                for prefix in _CC1_REPLAY_CONTROL_PREFIXES
            )
        ):
            raise ResolverError(
                "Clang -cc1 plan contains unsupported replay control option: "
                "{}".format(argument)
            )


def _cc1_replay_command(command, additions):
    # The primary input was verified as the final cc1 token.  Preserve every
    # attested driver-selected semantic option byte-for-byte and insert only
    # the resolver's fixed, bounded replay controls immediately before it.
    cc1 = command["cc1_arguments"]
    return (
        [str(command["frontend_target"])]
        + list(cc1[:-1])
        + list(additions)
        + [cc1[-1]]
    )


def _dependency_command(command, dependency_file):
    return _cc1_replay_command(
        command,
        [
            "-dependency-file",
            str(dependency_file),
            "-MT",
            "qemu-contract-resolver",
            "-sys-header-deps",
        ],
    )


def _frontend_command(command, ast_filter, action):
    return _cc1_replay_command(
        command, [action, "-ast-dump-filter={}".format(ast_filter)]
    )


def _attest_driver_plan(command, source_root, database_root, environment,
                        remaining_seconds, budget=None, deadline=None):
    timeout = min(10, remaining_seconds)
    if timeout <= 0:
        raise ResolverError("source-drift resolution exceeded its global deadline")
    arguments = _driver_plan_command(command["arguments"])
    try:
        completed = _run_bounded(
            arguments,
            command["directory"],
            environment,
            timeout,
            MAX_DIAGNOSTIC_BYTES,
            MAX_DIAGNOSTIC_BYTES,
        )
    except (OSError, subprocess.TimeoutExpired, _OutputLimitExceeded) as error:
        raise ResolverError("cannot attest Clang driver plan: {}".format(error)) from error
    if completed.returncode != 0:
        raise ResolverError(
            "Clang driver plan failed: {}".format(
                _normalize_diagnostic(
                    completed.stderr, source_root, database_root
                )
            )
        )

    jobs = []
    for line in completed.stderr.splitlines():
        try:
            tokens = shlex.split(line, posix=True)
        except ValueError as error:
            if "-cc1" in line:
                raise ResolverError(
                    "cannot parse Clang driver plan: {}".format(error)
                ) from error
            continue
        if "-cc1" not in tokens:
            continue
        if tokens.count("-cc1") != 1:
            raise ResolverError(
                "Clang driver plan has an ambiguous -cc1 job executable"
            )
        cc1_index = tokens.index("-cc1")
        if cc1_index != 1 or not tokens[0] or tokens[0].startswith("-"):
            raise ResolverError(
                "Clang driver plan has a missing or ambiguous -cc1 job executable"
            )
        jobs.append((tokens[0], tokens[cc1_index:]))
    if len(jobs) != 1:
        raise ResolverError(
            "anchor compile command must produce exactly one Clang -cc1 job; "
            "found {}".format(len(jobs))
        )

    frontend_name, cc1 = jobs[0]
    for argument in cc1[1:]:
        if _is_semantic_auxiliary_option(argument):
            raise ResolverError(
                "Clang -cc1 job uses unsupported semantic auxiliary input "
                "option: {}".format(argument)
            )
    frontend_invocation = _resolve_executable(
        frontend_name,
        command["directory"],
        environment,
        "Clang -cc1 job executable",
    )
    frontend_target = frontend_invocation.resolve()
    frontend_invocation_snapshot = _file_snapshot(
        frontend_invocation, with_hash=True, budget=budget, deadline=deadline
    )
    frontend_snapshot = _file_snapshot(
        frontend_target, with_hash=True, budget=budget, deadline=deadline
    )
    language = None
    index = 1
    while index < len(cc1):
        if cc1[index] == "-x":
            if index + 1 >= len(cc1):
                raise ResolverError("Clang -cc1 plan ends after -x")
            language = cc1[index + 1]
            index += 2
            continue
        index += 1
    if language not in _C_FAMILY_LANGUAGES:
        raise ResolverError(
            "anchor translation unit is not compiled as C-family source: -x {}".format(
                language or "<missing>"
            )
        )
    if len(cc1) < 2 or cc1[-1].startswith("-"):
        raise ResolverError("Clang -cc1 plan has no exact primary input")
    primary_input = _resolve_path(cc1[-1], command["directory"])
    if primary_input != command["file"]:
        raise ResolverError(
            "anchor compile command must have exactly one C-family input matching "
            "its file entry; Clang selected {}".format(primary_input)
        )
    _validate_cc1_replay_plan(cc1)

    normalized_plan = [
        _normalize_argument(
            str(frontend_invocation), source_root, database_root
        )
    ] + [
        _normalize_argument(token, source_root, database_root) for token in cc1
    ]
    command["language"] = language
    command["driver_plan_sha256"] = _value_hash(normalized_plan)
    command["frontend_invocation"] = frontend_invocation
    command["frontend_invocation_snapshot"] = frontend_invocation_snapshot
    command["frontend_target"] = frontend_target
    command["frontend_snapshot"] = frontend_snapshot
    command["cc1_arguments"] = tuple(cc1)
    command["cc1_executable"] = {
        "invocation": _display_path(
            frontend_invocation, source_root, database_root
        ),
        "resolved": _display_path(frontend_target, source_root, database_root),
        "bytes": frontend_snapshot["bytes"],
        "sha256": frontend_snapshot["sha256"],
    }
    normalized_replay = [
        _normalize_argument(str(frontend_target), source_root, database_root)
    ] + [
        _normalize_argument(token, source_root, database_root) for token in cc1
    ]
    command["cc1_replay_plan_sha256"] = _value_hash(normalized_replay)


def _ast_command(command, ast_filter):
    return _frontend_command(command, ast_filter, "-ast-dump=json")


def _ast_list_command(command, ast_filter):
    return _frontend_command(command, ast_filter, "-ast-list")


def _dependency_paths(path, directory, deadline=None):
    try:
        chunks = []
        consumed = 0
        with Path(path).open("rb") as stream:
            while True:
                _check_deadline(deadline)
                chunk = stream.read(64 * 1024)
                if not chunk:
                    break
                consumed += len(chunk)
                if consumed > MAX_DEPENDENCY_FILE_BYTES:
                    raise ResolverError(
                        "Clang dependency file exceeds the {}-byte limit".format(
                            MAX_DEPENDENCY_FILE_BYTES
                        )
                    )
                chunks.append(chunk)
        contents = b"".join(chunks).decode("utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise ResolverError("cannot read Clang dependency file: {}".format(error)) from error
    contents = contents.replace("\\\r\n", " ").replace("\\\n", " ")
    colon = contents.find(":")
    if colon < 0:
        raise ResolverError("Clang dependency file has no target separator")
    try:
        tokens = shlex.split(contents[colon + 1 :], posix=True)
    except ValueError as error:
        raise ResolverError("invalid Clang dependency file: {}".format(error)) from error
    if not tokens:
        raise ResolverError("Clang dependency file contains no inputs")
    if len(tokens) > MAX_DEPENDENCIES:
        raise ResolverError(
            "Clang dependency file has {} inputs; limit is {}".format(
                len(tokens), MAX_DEPENDENCIES
            )
        )
    resolved = set()
    for token in tokens:
        _check_deadline(deadline)
        resolved.add(_resolve_path(token, directory))
    return sorted(resolved)


def _selector_filters(names):
    # Exact selector filters keep AST output small and make the work bound
    # independent of unrelated declarations that happen to contain "map".
    return sorted(set(names))


def _json_stream(text):
    decoder = json.JSONDecoder()
    offset = 0
    while offset < len(text):
        while offset < len(text) and text[offset].isspace():
            offset += 1
        if offset == len(text):
            break
        try:
            value, offset = decoder.raw_decode(text, offset)
        except json.JSONDecodeError as error:
            raise ResolverError("clang AST output is not a JSON stream: {}".format(error))
        yield value


def _walk_ast(node):
    stack = [node]
    while stack:
        current = stack.pop()
        if not isinstance(current, dict):
            continue
        yield current
        children = current.get("inner", [])
        if isinstance(children, list):
            stack.extend(reversed(children))


def _matching_location(node, expected_header, directory):
    # Decl.loc is the declaration name token.  For a macro-produced
    # declaration, the outermost expansion site is the physical declaration
    # site.  A spelling location in the selected header is not sufficient: a
    # source file can invoke a declaration macro defined by that header.
    location = node.get("loc")
    if not isinstance(location, dict):
        return None
    while isinstance(location.get("expansionLoc"), dict):
        location = location["expansionLoc"]
    filename = location.get("file")
    if not isinstance(filename, str):
        return None
    if filename.startswith("<") and filename.endswith(">"):
        return None
    if _resolve_path(filename, directory) != expected_header:
        return None
    return location.get("line"), location.get("col")


def _function_declaration(node):
    if node.get("kind") != "FunctionDecl" or node.get("isImplicit"):
        return None
    name = node.get("name")
    function_type = node.get("type", {}).get("qualType")
    if not isinstance(name, str) or not isinstance(function_type, str):
        return None
    parameters = [
        child for child in node.get("inner", []) if child.get("kind") == "ParmVarDecl"
    ]
    parameter_types = []
    parameter_names = []
    for parameter in parameters:
        type_name = parameter.get("type", {}).get("qualType")
        if not isinstance(type_name, str):
            return None
        parameter_types.append(type_name)
        parameter_names.append(parameter.get("name", ""))
    return {
        "name": name,
        "mangled_name": node.get("mangledName", name),
        "prototype": function_type,
        "parameter_types": parameter_types,
        "parameter_names": parameter_names,
        "variadic": bool(node.get("variadic", False)),
    }


def _function_definition(node):
    declaration = _function_declaration(node)
    if declaration is None:
        return None
    body = next(
        (
            child
            for child in node.get("inner", [])
            if isinstance(child, dict) and child.get("kind") == "CompoundStmt"
        ),
        None,
    )
    if body is None:
        return None
    declaration["body"] = body
    return declaration


def _declaration_token_location(node):
    location = node.get("loc")
    if not isinstance(location, dict):
        return None
    offset = location.get("offset")
    line = location.get("line")
    column = location.get("col")
    # Clang may elide a repeated line number in JSON AST descendants.  Offset
    # and column remain present and identify the physical token exactly.
    if (
        not isinstance(offset, int)
        or (line is not None and not isinstance(line, int))
        or not isinstance(column, int)
    ):
        return None
    return offset, line, column


def _same_declaration_token_location(left, right):
    left_location = _declaration_token_location(left)
    right_location = _declaration_token_location(right)
    if left_location is None or right_location is None:
        return False
    left_offset, left_line, left_column = left_location
    right_offset, right_line, right_column = right_location
    if left_offset != right_offset or left_column != right_column:
        return False
    # Missing line is Clang's JSON location compression, not an unknown
    # source coordinate: the absolute byte offset is still exact.  If both
    # declarations spell out a line, require it to agree as well.
    return (
        left_line is None
        or right_line is None
        or left_line == right_line
    )


def _record_definition(node):
    """Return the source-level shape of a complete named record definition."""
    if (
        node.get("kind") != "RecordDecl"
        or node.get("isImplicit")
        or not node.get("completeDefinition")
    ):
        return None
    name = node.get("name")
    if not isinstance(name, str) or not name:
        return None
    children = node.get("inner", [])
    descendant_fields = [
        descendant
        for child in children
        if isinstance(child, dict)
        for descendant in _walk_ast(child)
        if descendant.get("kind") == "FieldDecl"
        and isinstance(descendant.get("name"), str)
        and descendant["name"]
    ]
    fields = []
    for child in children:
        if not isinstance(child, dict) or child.get("kind") not in {
            "FieldDecl",
            "IndirectFieldDecl",
        }:
            continue
        field_name = child.get("name")
        if child["kind"] == "FieldDecl" and not field_name:
            # An anonymous struct/union carrier is represented as an unnamed
            # implicit FieldDecl.  Its promoted members are attested through
            # the direct-child IndirectFieldDecl entries below.
            continue
        if not isinstance(field_name, str) or not field_name:
            return None
        declaration = child
        if child["kind"] == "IndirectFieldDecl":
            location = _declaration_token_location(child)
            if location is None:
                return None
            matches = [
                candidate
                for candidate in descendant_fields
                if candidate["name"] == field_name
                and _same_declaration_token_location(candidate, child)
            ]
            if len(matches) != 1:
                return None
            declaration = matches[0]
        field_type = declaration.get("type", {}).get("qualType")
        if not isinstance(field_type, str):
            return None
        fields.append(
            {
                "name": field_name,
                "type": field_type,
                # An IndirectFieldDecl is Clang's semantic declaration for a
                # field promoted through anonymous struct/union members (for
                # example QEMUIOVector.size).  It is deliberately accepted
                # only as a direct child of this complete RecordDecl.
                "access": (
                    "promoted"
                    if child["kind"] == "IndirectFieldDecl"
                    else "direct"
                ),
            }
        )
    return {"name": name, "fields": fields}


_DESIGNATED_INITIALIZER_RE = re.compile(
    rb"\.\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*&?\s*"
    rb"([A-Za-z_][A-Za-z0-9_]*)"
)


def _source_range_text(node, source_bytes):
    source_range = node.get("range")
    if not isinstance(source_range, dict):
        return None
    begin = source_range.get("begin")
    end = source_range.get("end")
    if not isinstance(begin, dict) or not isinstance(end, dict):
        return None
    begin_offset = begin.get("offset")
    end_offset = end.get("offset")
    token_length = end.get("tokLen", 1)
    if (
        not isinstance(begin_offset, int)
        or not isinstance(end_offset, int)
        or not isinstance(token_length, int)
        or begin_offset < 0
        or end_offset < begin_offset
        or token_length <= 0
        or end_offset + token_length > len(source_bytes)
    ):
        return None
    return source_bytes[begin_offset : end_offset + token_length]


def _designated_initializer_bindings(source_text):
    if not isinstance(source_text, bytes):
        return []
    return [
        {
            "field": match.group(1).decode("ascii"),
            "target": match.group(2).decode("ascii"),
        }
        for match in _DESIGNATED_INITIALIZER_RE.finditer(source_text)
    ]


def _referenced_function_declarations(node):
    references = []
    for descendant in _walk_ast(node):
        if descendant.get("kind") != "DeclRefExpr":
            continue
        declaration = descendant.get("referencedDecl")
        if not isinstance(declaration, dict) or declaration.get("kind") != "FunctionDecl":
            continue
        name = declaration.get("name")
        type_name = declaration.get("type", {}).get("qualType")
        if isinstance(name, str) and isinstance(type_name, str):
            references.append({"name": name, "type": type_name})
    unique = {
        (reference["name"], _canonical_type(reference["type"])): reference
        for reference in references
    }
    return [unique[key] for key in sorted(unique)]


def _registration_variable(node, expected_source, directory, source_bytes):
    if node.get("kind") != "VarDecl" or node.get("isImplicit"):
        return None
    name = node.get("name")
    type_name = node.get("type", {}).get("qualType")
    if not isinstance(name, str) or not isinstance(type_name, str):
        return None
    location = _source_location(node, expected_source, directory)
    if location is None:
        return None
    source_text = _source_range_text(node, source_bytes)
    if source_text is None:
        return None
    line, column, is_macro = location
    return {
        "name": name,
        "type": type_name,
        "line": line,
        "column": column,
        "macro": is_macro,
        "designated_bindings": _designated_initializer_bindings(source_text),
        "function_references": _referenced_function_declarations(node),
    }


def _unwrap_expression(node):
    wrappers = {
        "CStyleCastExpr",
        "ImplicitCastExpr",
        "ParenExpr",
        "UnaryOperator",
    }
    current = node
    while isinstance(current, dict) and current.get("kind") in wrappers:
        children = [
            child for child in current.get("inner", []) if isinstance(child, dict)
        ]
        if len(children) != 1:
            break
        current = children[0]
    return current


def _callback_assignment(node, expected_source, directory, source_bytes):
    if node.get("kind") != "BinaryOperator" or node.get("opcode") != "=":
        return None
    children = [child for child in node.get("inner", []) if isinstance(child, dict)]
    if len(children) != 2:
        return None
    member = _unwrap_expression(children[0])
    if not isinstance(member, dict) or member.get("kind") != "MemberExpr":
        return None
    field = member.get("name")
    member_type = member.get("type", {}).get("qualType")
    member_children = [
        child for child in member.get("inner", []) if isinstance(child, dict)
    ]
    if (
        not isinstance(field, str)
        or not isinstance(member_type, str)
        or len(member_children) != 1
    ):
        return None
    base_type = member_children[0].get("type", {}).get("qualType")
    if not isinstance(base_type, str):
        return None
    references = _referenced_function_declarations(children[1])
    if len(references) != 1:
        return None
    location = _source_location(
        node,
        expected_source,
        directory,
        allow_inherited=True,
        source_bytes=source_bytes,
    )
    if location is None:
        return None
    line, column, is_macro = location
    return {
        "field": field,
        "member_type": member_type,
        "base_type": base_type,
        "target": references[0]["name"],
        "target_type": references[0]["type"],
        "line": line,
        "column": column,
        "macro": is_macro,
    }


def _source_location(
    node, expected_source, directory, allow_inherited=False, source_bytes=None
):
    location = node.get("loc")
    if not isinstance(location, dict) or "line" not in location:
        location = node.get("range", {}).get("begin")
    if not isinstance(location, dict):
        return None
    is_macro = "spellingLoc" in location or "expansionLoc" in location
    while isinstance(location.get("expansionLoc"), dict):
        location = location["expansionLoc"]
    filename = location.get("file")
    if isinstance(filename, str):
        if filename.startswith("<") and filename.endswith(">"):
            return None
        if _resolve_path(filename, directory) != expected_source:
            return None
    elif not allow_inherited:
        return None
    line = location.get("line")
    column = location.get("col")
    if not isinstance(line, int):
        # Clang's JSON AST compresses repeated physical locations.  Descendant
        # expressions can retain only their byte offset and column even though
        # the enclosing declaration has the source file and line.  Protocol
        # body scans deliberately allow that inherited context; recover the
        # physical line from the already-attested source instead of silently
        # dropping otherwise exact event sites.
        offset = location.get("offset")
        if not allow_inherited or not isinstance(offset, int) or offset < 0:
            return None
        if source_bytes is None:
            try:
                source_bytes = expected_source.read_bytes()
            except OSError:
                return None
        if offset > len(source_bytes):
            return None
        line = source_bytes.count(b"\n", 0, offset) + 1
        line_start = source_bytes.rfind(b"\n", 0, offset) + 1
        physical_column = offset - line_start + 1
        if isinstance(column, int) and column != physical_column:
            return None
        column = physical_column
    if not isinstance(column, int):
        return None
    return line, column, is_macro


def _direct_callee(call):
    children = call.get("inner", [])
    if not children or not isinstance(children[0], dict):
        return None
    for node in _walk_ast(children[0]):
        if node.get("kind") != "DeclRefExpr":
            continue
        declaration = node.get("referencedDecl")
        if not isinstance(declaration, dict) or declaration.get("kind") != "FunctionDecl":
            continue
        name = declaration.get("name")
        prototype = declaration.get("type", {}).get("qualType")
        if isinstance(name, str) and isinstance(prototype, str):
            return name, prototype
    return None


def _updated_member(node):
    children = node.get("inner", [])
    if not children or not isinstance(children[0], dict):
        return None
    for descendant in _walk_ast(children[0]):
        if descendant.get("kind") == "MemberExpr":
            return descendant
    return None


def _member_record_type(member):
    children = member.get("inner", [])
    if not children or not isinstance(children[0], dict):
        return None
    type_info = children[0].get("type", {})
    type_name = type_info.get("desugaredQualType", type_info.get("qualType"))
    if not isinstance(type_name, str):
        return None
    canonical = _canonical_type(type_name)
    canonical = re.sub(r"^(?:const|volatile|restrict)+", "", canonical)
    canonical = canonical.rstrip("*")
    return re.sub(r"^(?:struct|class|union)", "", canonical)


def _protocol_selector_matches(node, selector, contracts_by_id):
    kind = selector["kind"]
    if kind in {"transfer-call", "function-call"}:
        if node.get("kind") not in {"CallExpr", "CXXMemberCallExpr"}:
            return False
        callee = _direct_callee(node)
        if callee is None:
            return False
        name, prototype = callee
        if kind == "transfer-call":
            contract = contracts_by_id[selector["contract_id"]]
            expected_name = contract["selector"]["name"]
            expected_prototype = _expected_prototype(contract)
        else:
            expected_name = selector["name"]
            expected_prototype = _expected_prototype(selector)
        return name == expected_name and _canonical_type(prototype) == _canonical_type(
            expected_prototype
        )

    operation = selector["operation"]
    unary = {
        "pre-decrement": ("--", False),
        "post-decrement": ("--", True),
        "pre-increment": ("++", False),
        "post-increment": ("++", True),
    }
    if operation in unary:
        opcode, postfix = unary[operation]
        if (
            node.get("kind") != "UnaryOperator"
            or node.get("opcode") != opcode
            or bool(node.get("isPostfix")) != postfix
        ):
            return False
    else:
        opcode = {"add-assign": "+=", "subtract-assign": "-="}[operation]
        if node.get("kind") != "CompoundAssignOperator" or node.get("opcode") != opcode:
            return False
    member = _updated_member(node)
    return (
        member is not None
        and member.get("name") == selector["field"]
        and _member_record_type(member) == selector["record_type"]
    )


def _canonical_type(type_name):
    # In C, QEMU's source-level ``bool`` macro is represented as ``_Bool`` in
    # Clang's AST.  They are the same type for contract matching; retaining the
    # catalog spelling keeps the model shared with C++ fixtures and reports.
    type_name = re.sub(r"\b_Bool\b", "bool", type_name)
    return "".join(type_name.split())


def _expected_prototype(contract):
    prototype = contract["prototype"]
    return "{} ({})".format(
        prototype["return_type"],
        ", ".join(parameter["type"] for parameter in prototype["parameters"]),
    )


def _declaration_key(declaration):
    # Parameter names are not part of a C or C++ function type and may differ
    # across legal redeclarations.  Keep every observed spelling for catalog
    # name validation, but canonicalize declaration identity by linkage name
    # and type only.
    return (
        declaration["path"],
        declaration["mangled_name"],
        _canonical_type(declaration["prototype"]),
        declaration["variadic"],
    )


def _record_definition_key(definition):
    return (
        definition["path"],
        definition["name"],
        tuple(
            (
                field["name"],
                _canonical_type(field["type"]),
                field["access"],
            )
            for field in definition["fields"]
        ),
    )


def _protocol_definition_observation(
    node, protocol, source_path, directory, contracts_by_id
):
    definition = _function_definition(node)
    if definition is None or definition["name"] != protocol["scope"]["name"]:
        return None
    if node.get("parentDeclContextId") is not None:
        return None
    location = _source_location(node, source_path, directory)
    if location is None or location[2]:
        return None
    line, column, _ = location
    try:
        source_bytes = source_path.read_bytes()
    except OSError:
        return None

    event_reports = []
    body_nodes = list(_walk_ast(definition["body"]))
    for event in protocol["events"]:
        selector_reports = []
        for selector in event["selectors"]:
            sites = []
            for body_node in body_nodes:
                if not _protocol_selector_matches(
                    body_node, selector, contracts_by_id
                ):
                    continue
                site = _source_location(
                    body_node, source_path, directory, allow_inherited=True,
                    source_bytes=source_bytes,
                )
                # Macro-expanded events are deliberately not accepted as exact
                # syntactic selectors.  They require a distinct adapter model.
                if site is None or site[2]:
                    continue
                sites.append({"line": site[0], "column": site[1]})
            sites.sort(key=lambda site: (site["line"], site["column"]))
            observed_count = len(sites)
            if observed_count == selector["expected_count"]:
                status = "matched"
            elif observed_count == 0:
                status = "missing"
            else:
                status = "cardinality"
            selector_reports.append(
                {
                    "selector": selector,
                    "expected_count": selector["expected_count"],
                    "observed_count": observed_count,
                    "status": status,
                    "sites": sites,
                }
            )
        event_reports.append(
            {
                "stage": event["stage"],
                "status": (
                    "matched"
                    if all(
                        selector["status"] == "matched"
                        for selector in selector_reports
                    )
                    else "drift"
                ),
                "selectors": selector_reports,
            }
        )

    observed = dict(definition)
    del observed["body"]
    observed.update(
        {
            "path": protocol["scope"]["source"],
            "line": line,
            "column": column,
            "events": event_reports,
        }
    )
    return observed


def resolve_catalog(catalog, schema, compile_commands_path, source_root,
                    timeout_seconds=120, validation_profile="production"):
    catalog_tool.validate_catalog(catalog, profile=validation_profile)
    catalog_tool.validate_schema_document(schema)
    if not isinstance(timeout_seconds, int) or timeout_seconds <= 0:
        raise ResolverError("timeout_seconds must be a positive integer")

    started = time.monotonic()
    deadline = started + timeout_seconds
    attestation_budget = _AttestationBudget(
        MAX_AGGREGATE_ATTESTED_BYTES, deadline
    )
    source_root = Path(source_root).resolve()
    compile_commands_path = Path(compile_commands_path).resolve()
    database_root = compile_commands_path.parent
    if not source_root.is_dir():
        raise ResolverError("source root is not a directory: {}".format(source_root))

    resolver_path = Path(__file__).resolve()
    generator_path = Path(catalog_tool.__file__).resolve()
    resolver_snapshot = _file_snapshot(
        resolver_path,
        with_hash=True,
        budget=attestation_budget,
        deadline=deadline,
    )
    generator_snapshot = _file_snapshot(
        generator_path,
        with_hash=True,
        budget=attestation_budget,
        deadline=deadline,
    )
    database_snapshot = _file_snapshot(
        compile_commands_path,
        with_hash=True,
        budget=attestation_budget,
        deadline=deadline,
        maximum_bytes=MAX_COMPILE_DATABASE_BYTES,
        limit_name="compile_commands.json",
    )
    contracts = sorted(catalog["contracts"], key=lambda contract: contract["id"])
    contracts_by_id = {contract["id"]: contract for contract in contracts}
    callbacks = sorted(
        catalog["callback_bindings"], key=lambda callback: callback["id"]
    )
    protocols = sorted(catalog["protocols"], key=lambda protocol: protocol["id"])
    headers = {}
    header_snapshots = {}
    protocol_sources = {}
    protocol_source_snapshots = {}
    translation_units = {}
    translation_unit_contracts = defaultdict(list)
    translation_unit_callback_slots = defaultdict(list)
    translation_unit_callback_registrations = defaultdict(list)
    translation_unit_protocols = defaultdict(list)
    translation_unit_member_records = defaultdict(dict)
    contract_member_operands = {}
    callback_slot_translation_units = {}
    callback_registration_translation_units = {}
    callback_registration_root_keys = {}
    registration_roots = {}
    by_name = {}

    def register_header(configured, kind):
        header = (source_root / configured).resolve()
        try:
            header.relative_to(source_root)
        except ValueError:
            raise ResolverError("{} escapes source root: {}".format(kind, configured))
        if not header.is_file():
            raise ResolverError("{} is missing: {}".format(kind, configured))
        if configured not in headers:
            headers[configured] = header
            header_snapshots[configured] = _file_snapshot(
                header,
                with_hash=True,
                budget=attestation_budget,
                deadline=deadline,
            )
        elif headers[configured] != header:
            raise ResolverError("{} resolves inconsistently: {}".format(kind, configured))
        return header

    def register_translation_unit(configured, kind):
        translation_unit = (source_root / configured).resolve()
        try:
            translation_unit.relative_to(source_root)
        except ValueError:
            raise ResolverError("{} escapes source root: {}".format(kind, configured))
        if not translation_unit.is_file():
            raise ResolverError("{} is missing: {}".format(kind, configured))
        translation_units[configured] = translation_unit
        return translation_unit

    for contract in contracts:
        _check_deadline(deadline)
        selector = contract["selector"]
        register_header(selector["header"], "selector header")
        translation_unit = (source_root / selector["translation_unit"]).resolve()
        try:
            translation_unit.relative_to(source_root)
        except ValueError:
            raise ResolverError(
                "translation-unit anchor escapes source root: {}".format(
                    selector["translation_unit"]
                )
            )
        if not translation_unit.is_file():
            raise ResolverError(
                "translation-unit anchor is missing: {}".format(
                    selector["translation_unit"]
                )
            )
        translation_units[selector["translation_unit"]] = translation_unit
        translation_unit_contracts[translation_unit].append(contract)
        by_name[selector["name"]] = contract
        member_operands = []
        for operand in contract["operands"]:
            if operand["source"] != "argument_member":
                continue
            member_operands.append(operand)
            for step in operand["path"]:
                register_header(step["header"], "member-path header")
                key = (step["record_type"], step["header"])
                translation_unit_member_records[translation_unit][key] = {
                    "record_type": step["record_type"],
                    "header": step["header"],
                }
        contract_member_operands[contract["id"]] = member_operands

    for callback in callbacks:
        _check_deadline(deadline)
        slot = callback["slot"]
        registration = callback["registration"]
        register_header(slot["header"], "callback slot header")
        register_header(registration["header"], "callback registration header")
        slot_translation_unit = register_translation_unit(
            slot["translation_unit"], "callback slot translation-unit anchor"
        )
        registration_translation_unit = register_translation_unit(
            registration["translation_unit"],
            "callback registration translation-unit anchor",
        )
        callback_id = callback["id"]
        callback_slot_translation_units[callback_id] = slot_translation_unit
        callback_registration_translation_units[
            callback_id
        ] = registration_translation_unit
        root_key = (
            registration_translation_unit,
            registration["variable"],
            registration["initializer"],
        )
        callback_registration_root_keys[callback_id] = root_key
        root = registration_roots.setdefault(
            root_key,
            {
                "translation_unit": registration_translation_unit,
                "variable": registration["variable"],
                "initializer": registration["initializer"],
                "callbacks": [],
            },
        )
        root["callbacks"].append(callback)
        translation_unit_callback_slots[slot_translation_unit].append(callback)
        translation_unit_callback_registrations[
            registration_translation_unit
        ].append(callback)
        translation_unit_member_records[slot_translation_unit][
            (slot["record_type"], slot["header"])
        ] = {
            "record_type": slot["record_type"],
            "header": slot["header"],
        }
        translation_unit_member_records[registration_translation_unit][
            (registration["record_type"], registration["header"])
        ] = {
            "record_type": registration["record_type"],
            "header": registration["header"],
        }

        for entry_input in callback["entry_inputs"]:
            if entry_input["source"] != "argument_member":
                continue
            for step in entry_input["path"]:
                register_header(step["header"], "callback entry-input header")
                translation_unit_member_records[slot_translation_unit][
                    (step["record_type"], step["header"])
                ] = {
                    "record_type": step["record_type"],
                    "header": step["header"],
                }
    for protocol in protocols:
        _check_deadline(deadline)
        scope = protocol["scope"]
        source = (source_root / scope["source"]).resolve()
        translation_unit = (source_root / scope["translation_unit"]).resolve()
        for kind, configured, resolved in (
            ("protocol scope source", scope["source"], source),
            ("protocol translation-unit anchor", scope["translation_unit"], translation_unit),
        ):
            try:
                resolved.relative_to(source_root)
            except ValueError:
                raise ResolverError("{} escapes source root: {}".format(kind, configured))
            if not resolved.is_file():
                raise ResolverError("{} is missing: {}".format(kind, configured))
        protocol_sources[scope["source"]] = source
        protocol_source_snapshots[scope["source"]] = _file_snapshot(
            source,
            with_hash=True,
            budget=attestation_budget,
            deadline=deadline,
        )
        translation_units[scope["translation_unit"]] = translation_unit
        translation_unit_protocols[translation_unit].append(protocol)

    if len(translation_units) > MAX_ANCHOR_COMMANDS:
        raise ResolverError(
            "catalog has {} translation-unit anchors; limit is {}".format(
                len(translation_units), MAX_ANCHOR_COMMANDS
            )
        )

    all_commands, raw_command_count = _load_compile_commands(
        compile_commands_path, source_root, deadline=deadline
    )
    commands = []
    for configured, translation_unit in sorted(translation_units.items()):
        _check_deadline(deadline)
        matches = [command for command in all_commands if command["file"] == translation_unit]
        allows_protocol_contexts = bool(
            translation_unit_protocols[translation_unit]
        )
        if not matches or (len(matches) != 1 and not allows_protocol_contexts):
            raise ResolverError(
                "translation-unit anchor {} has {} distinct compile commands; expected {}".format(
                    configured,
                    len(matches),
                    "at least 1 protocol context" if allows_protocol_contexts else "1",
                )
            )
        for command in matches:
            if not command["directory"].is_dir():
                raise ResolverError(
                    "anchor compilation directory does not exist: {}".format(
                        command["directory"]
                    )
                )
            _validate_driver_command_shape(command)
            commands.append(command)
    if len(commands) > MAX_ANCHOR_COMMANDS:
        raise ResolverError(
            "catalog selects {} anchor compile commands; limit is {}".format(
                len(commands), MAX_ANCHOR_COMMANDS
            )
        )

    environment, semantic_environment = _controlled_environment(
        source_root, database_root
    )
    compiler_snapshots = {}
    compiler_invocation_snapshots = {}
    frontend_snapshots = {}
    frontend_invocation_snapshots = {}
    for command in commands:
        _check_deadline(deadline)
        remaining = deadline - time.monotonic()
        _resolve_compiler(
            command,
            source_root,
            database_root,
            environment,
            remaining,
            budget=attestation_budget,
            deadline=deadline,
        )
        for path_key, snapshot_key, snapshots in (
            (
                "compiler_invocation",
                "compiler_invocation_snapshot",
                compiler_invocation_snapshots,
            ),
            ("compiler_target", "compiler_snapshot", compiler_snapshots),
        ):
            path = command[path_key]
            snapshot = command[snapshot_key]
            previous = snapshots.get(path)
            if previous is not None and previous != snapshot:
                raise ResolverError(
                    "Clang compiler changed between anchor attestations: {}".format(
                        path
                    )
                )
            snapshots[path] = snapshot
        remaining = deadline - time.monotonic()
        _attest_driver_plan(
            command,
            source_root,
            database_root,
            environment,
            remaining,
            budget=attestation_budget,
            deadline=deadline,
        )
        for path_key, snapshot_key, snapshots in (
            (
                "frontend_invocation",
                "frontend_invocation_snapshot",
                frontend_invocation_snapshots,
            ),
            ("frontend_target", "frontend_snapshot", frontend_snapshots),
        ):
            path = command[path_key]
            snapshot = command[snapshot_key]
            previous = snapshots.get(path)
            if previous is not None and previous != snapshot:
                raise ResolverError(
                    "Clang -cc1 job executable changed between anchor "
                    "attestations: {}".format(path)
                )
            snapshots[path] = snapshot

    source_snapshots = {
        command["file"]: _file_snapshot(
            command["file"],
            with_hash=True,
            budget=attestation_budget,
            deadline=deadline,
        )
        for command in commands
    }
    filters = _selector_filters(
        list(by_name)
        + [protocol["scope"]["name"] for protocol in protocols]
        + [
            name
            for root in registration_roots.values()
            for name in (root["variable"], root["initializer"])
        ]
        + [
            record["record_type"]
            for records in translation_unit_member_records.values()
            for record in records.values()
        ]
    )
    run_count = sum(
        (
            len(translation_unit_contracts[command["file"]])
            + len(translation_unit_protocols[command["file"]])
        )
        * (2 if "++" in command["language"] else 1)
        + len(translation_unit_member_records[command["file"]])
        + 2
        * sum(
            root["translation_unit"] == command["file"]
            for root in registration_roots.values()
        )
        for command in commands
    )
    if run_count > MAX_AST_RUNS:
        raise ResolverError(
            "catalog resolution requires {} Clang runs; limit is {}".format(
                run_count, MAX_AST_RUNS
            )
        )

    declarations = {contract["id"]: {} for contract in contracts}
    record_definitions = {
        key: {}
        for records in translation_unit_member_records.values()
        for key in records
    }
    protocol_definitions = {protocol["id"]: {} for protocol in protocols}
    protocol_analyzed_contexts = {protocol["id"]: set() for protocol in protocols}
    registration_variable_declarations = {
        key: {} for key in registration_roots
    }
    registration_initializer_definitions = {
        key: {} for key in registration_roots
    }
    command_errors = []
    deadline_exhausted = False
    dependency_snapshots = {}
    dependency_temp = tempfile.TemporaryDirectory(prefix="qemu-contract-resolver-")
    dependency_root = Path(dependency_temp.name)

    def run_frontend(command, ast_filter, arguments, output_kind):
        nonlocal deadline_exhausted
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            if not deadline_exhausted:
                command_errors.append(
                    {
                        "command_id": command["id"],
                        "file": _display_path(
                            command["file"], source_root, database_root
                        ),
                        "filter": ast_filter,
                        "kind": "global-timeout",
                        "message": "source-drift resolution exceeded {} seconds".format(
                            timeout_seconds
                        ),
                    }
                )
                deadline_exhausted = True
            return None
        try:
            completed = _run_bounded(
                arguments,
                command["directory"],
                environment,
                remaining,
                MAX_AST_OUTPUT_BYTES,
                MAX_DIAGNOSTIC_BYTES,
            )
        except subprocess.TimeoutExpired:
            command_errors.append(
                {
                    "command_id": command["id"],
                    "file": _display_path(command["file"], source_root, database_root),
                    "filter": ast_filter,
                    "kind": "global-timeout",
                    "message": "source-drift resolution exceeded {} seconds".format(
                        timeout_seconds
                    ),
                }
            )
            deadline_exhausted = True
            return None
        except _OutputLimitExceeded as error:
            command_errors.append(
                {
                    "command_id": command["id"],
                    "file": _display_path(command["file"], source_root, database_root),
                    "filter": ast_filter,
                    "kind": "output-limit",
                    "message": "{} {} exceeded {} bytes".format(
                        output_kind, error.stream, error.limit
                    ),
                }
            )
            return None
        except OSError as error:
            command_errors.append(
                {
                    "command_id": command["id"],
                    "file": _display_path(command["file"], source_root, database_root),
                    "filter": ast_filter,
                    "kind": "spawn",
                    "message": str(error),
                }
            )
            return None
        if completed.returncode != 0:
            command_errors.append(
                {
                    "command_id": command["id"],
                    "file": _display_path(command["file"], source_root, database_root),
                    "filter": ast_filter,
                    "kind": "compiler",
                    "returncode": completed.returncode,
                    "message": _normalize_diagnostic(
                        completed.stderr, source_root, database_root
                    ),
                }
            )
            return None
        return completed

    def snapshot_dependencies(command, dependency_file, phase):
        nonlocal deadline_exhausted
        completed = run_frontend(
            command,
            phase,
            _dependency_command(command, dependency_file),
            "Clang dependency",
        )
        if completed is None:
            return None
        try:
            snapshots = {}
            for dependency in _dependency_paths(
                dependency_file, command["directory"], deadline=deadline
            ):
                _check_deadline(deadline)
                snapshots[dependency] = _file_snapshot(
                    dependency,
                    with_hash=True,
                    budget=attestation_budget,
                    deadline=deadline,
                )
            return snapshots
        except _DeadlineExceeded:
            if not deadline_exhausted:
                command_errors.append(
                    {
                        "command_id": command["id"],
                        "file": _display_path(
                            command["file"], source_root, database_root
                        ),
                        "filter": phase,
                        "kind": "global-timeout",
                        "message": "source-drift resolution exceeded {} seconds".format(
                            timeout_seconds
                        ),
                    }
                )
                deadline_exhausted = True
            return None
        except ResolverError as error:
            command_errors.append(
                {
                    "command_id": command["id"],
                    "file": _display_path(
                        command["file"], source_root, database_root
                    ),
                    "filter": phase,
                    "kind": "dependency",
                    "message": _normalize_diagnostic(
                        str(error), source_root, database_root
                    ),
                }
            )
            return None

    for command in sorted(commands, key=lambda item: item["file"].as_posix()):
        command_contracts = sorted(
            translation_unit_contracts[command["file"]],
            key=lambda contract: contract["selector"]["name"],
        )
        command_protocols = sorted(
            translation_unit_protocols[command["file"]],
            key=lambda protocol: protocol["scope"]["name"],
        )
        command_member_records = [
            translation_unit_member_records[command["file"]][key]
            for key in sorted(translation_unit_member_records[command["file"]])
        ]
        command_registration_roots = [
            (key, registration_roots[key])
            for key in sorted(
                registration_roots,
                key=lambda item: (item[0].as_posix(), item[1], item[2]),
            )
            if registration_roots[key]["translation_unit"] == command["file"]
        ]
        dependency_file_before = dependency_root / (command["id"] + ".before.d")
        dependencies_before = snapshot_dependencies(
            command, dependency_file_before, "<dependencies-before>"
        )
        if dependencies_before is None:
            continue
        for contract in command_contracts:
            if deadline_exhausted:
                break
            ast_filter = contract["selector"]["name"]
            if "++" in command["language"]:
                listed = run_frontend(
                    command,
                    ast_filter,
                    _ast_list_command(command, ast_filter),
                    "Clang AST-name",
                )
                if listed is None:
                    continue
                qualified = sorted(
                    {
                        line.strip()
                        for line in listed.stdout.splitlines()
                        if line.strip().endswith("::" + ast_filter)
                    }
                )
                if qualified:
                    command_errors.append(
                        {
                            "command_id": command["id"],
                            "file": _display_path(
                                command["file"], source_root, database_root
                            ),
                            "filter": ast_filter,
                            "kind": "non-global-selector",
                            "message": "qualified declaration(s): {}".format(
                                ", ".join(qualified)
                            ),
                        }
                    )
                    continue

            completed = run_frontend(
                command,
                ast_filter,
                _ast_command(command, ast_filter),
                "Clang AST",
            )
            if completed is None:
                continue
            try:
                roots = _json_stream(completed.stdout)
                for root in roots:
                    for node in _walk_ast(root):
                        declaration = _function_declaration(node)
                        if declaration is None or declaration["name"] != ast_filter:
                            continue
                        # With Clang's filtered JSON dump, a file-scope C
                        # FunctionDecl is emitted as a root without a parent
                        # context.  A block-scope declaration carries its
                        # lexical parent's ID even though it has external
                        # linkage.  It must not impersonate a catalog API.
                        if node.get("parentDeclContextId") is not None:
                            command_errors.append(
                                {
                                    "command_id": command["id"],
                                    "file": _display_path(
                                        command["file"], source_root, database_root
                                    ),
                                    "filter": ast_filter,
                                    "kind": "non-global-selector",
                                    "message": "block-scope function declaration",
                                }
                            )
                            continue
                        selector = contract["selector"]
                        location = _matching_location(
                            node, headers[selector["header"]], command["directory"]
                        )
                        if location is None:
                            continue
                        line, column = location
                        observed = dict(declaration)
                        observed.update(
                            {
                                "path": selector["header"],
                                "line": line,
                                "column": column,
                            }
                        )
                        key = _declaration_key(observed)
                        record = declarations[contract["id"]].setdefault(
                            key,
                            {
                                "declaration": observed,
                                "contexts": set(),
                                "parameter_name_sets": set(),
                                "sites": set(),
                            },
                        )
                        record["contexts"].add(command["id"])
                        record["parameter_name_sets"].add(
                            tuple(observed["parameter_names"])
                        )
                        record["sites"].add((line or 0, column or 0))
                        current_site = (
                            record["declaration"].get("line") or 0,
                            record["declaration"].get("column") or 0,
                        )
                        if (line or 0, column or 0) < current_site:
                            record["declaration"] = observed
            except ResolverError as error:
                command_errors.append(
                    {
                        "command_id": command["id"],
                        "file": _display_path(
                            command["file"], source_root, database_root
                        ),
                        "filter": ast_filter,
                        "kind": "ast-json",
                        "message": str(error),
                    }
                )
        for member_record in command_member_records:
            if deadline_exhausted:
                break
            ast_filter = member_record["record_type"]
            completed = run_frontend(
                command,
                ast_filter,
                _ast_command(command, ast_filter),
                "Clang AST",
            )
            if completed is None:
                continue
            try:
                record_key = (
                    member_record["record_type"],
                    member_record["header"],
                )
                expected_header = headers[member_record["header"]]
                for root in _json_stream(completed.stdout):
                    for node in _walk_ast(root):
                        definition = _record_definition(node)
                        if (
                            definition is None
                            or definition["name"] != member_record["record_type"]
                        ):
                            continue
                        location = _matching_location(
                            node, expected_header, command["directory"]
                        )
                        if location is None:
                            continue
                        if node.get("parentDeclContextId") is not None:
                            command_errors.append(
                                {
                                    "command_id": command["id"],
                                    "file": _display_path(
                                        command["file"], source_root, database_root
                                    ),
                                    "filter": ast_filter,
                                    "kind": "non-global-member-record",
                                    "message": "qualified or local record definition in "
                                    + member_record["header"],
                                }
                            )
                            continue
                        line, column = location
                        observed = dict(definition)
                        observed.update(
                            {
                                "path": member_record["header"],
                                "line": line,
                                "column": column,
                            }
                        )
                        definition_key = _record_definition_key(observed)
                        record = record_definitions[record_key].setdefault(
                            definition_key,
                            {
                                "definition": observed,
                                "contexts": set(),
                                "sites": set(),
                            },
                        )
                        record["contexts"].add(command["id"])
                        record["sites"].add((line or 0, column or 0))
                        current_site = (
                            record["definition"].get("line") or 0,
                            record["definition"].get("column") or 0,
                        )
                        if (line or 0, column or 0) < current_site:
                            record["definition"] = observed
            except ResolverError as error:
                command_errors.append(
                    {
                        "command_id": command["id"],
                        "file": _display_path(
                            command["file"], source_root, database_root
                        ),
                        "filter": ast_filter,
                        "kind": "ast-json",
                        "message": str(error),
                    }
                )
        for root_key, registration_root in command_registration_roots:
            if deadline_exhausted:
                break
            try:
                registration_source_bytes = command["file"].read_bytes()
            except OSError as error:
                command_errors.append(
                    {
                        "command_id": command["id"],
                        "file": _display_path(
                            command["file"], source_root, database_root
                        ),
                        "filter": registration_root["variable"],
                        "kind": "source-read",
                        "message": str(error),
                    }
                )
                continue

            variable_filter = registration_root["variable"]
            completed = run_frontend(
                command,
                variable_filter,
                _ast_command(command, variable_filter),
                "Clang AST",
            )
            if completed is not None:
                try:
                    for ast_root in _json_stream(completed.stdout):
                        for node in _walk_ast(ast_root):
                            observation = _registration_variable(
                                node,
                                command["file"],
                                command["directory"],
                                registration_source_bytes,
                            )
                            if (
                                observation is None
                                or observation["name"] != variable_filter
                            ):
                                continue
                            if node.get("parentDeclContextId") is not None:
                                command_errors.append(
                                    {
                                        "command_id": command["id"],
                                        "file": _display_path(
                                            command["file"], source_root, database_root
                                        ),
                                        "filter": variable_filter,
                                        "kind": "non-global-registration-variable",
                                        "message": "local TypeInfo registration variable",
                                    }
                                )
                                continue
                            observation["path"] = next(
                                callback["registration"]["translation_unit"]
                                for callback in registration_root["callbacks"]
                            )
                            key = (
                                observation["path"],
                                observation["name"],
                                _canonical_type(observation["type"]),
                                tuple(
                                    (binding["field"], binding["target"])
                                    for binding in observation["designated_bindings"]
                                ),
                                tuple(
                                    (
                                        reference["name"],
                                        _canonical_type(reference["type"]),
                                    )
                                    for reference in observation["function_references"]
                                ),
                            )
                            registration_variable_declarations[root_key][key] = observation
                except ResolverError as error:
                    command_errors.append(
                        {
                            "command_id": command["id"],
                            "file": _display_path(
                                command["file"], source_root, database_root
                            ),
                            "filter": variable_filter,
                            "kind": "ast-json",
                            "message": str(error),
                        }
                    )

            initializer_filter = registration_root["initializer"]
            completed = run_frontend(
                command,
                initializer_filter,
                _ast_command(command, initializer_filter),
                "Clang AST",
            )
            if completed is not None:
                try:
                    for ast_root in _json_stream(completed.stdout):
                        for node in _walk_ast(ast_root):
                            definition = _function_definition(node)
                            if (
                                definition is None
                                or definition["name"] != initializer_filter
                            ):
                                continue
                            if node.get("parentDeclContextId") is not None:
                                command_errors.append(
                                    {
                                        "command_id": command["id"],
                                        "file": _display_path(
                                            command["file"], source_root, database_root
                                        ),
                                        "filter": initializer_filter,
                                        "kind": "non-global-registration-initializer",
                                        "message": "local class initializer definition",
                                    }
                                )
                                continue
                            location = _source_location(
                                node, command["file"], command["directory"]
                            )
                            if location is None:
                                continue
                            line, column, is_macro = location
                            assignments = []
                            for descendant in _walk_ast(definition["body"]):
                                assignment = _callback_assignment(
                                    descendant,
                                    command["file"],
                                    command["directory"],
                                    registration_source_bytes,
                                )
                                if assignment is not None:
                                    assignments.append(assignment)
                            observed = dict(definition)
                            del observed["body"]
                            observed.update(
                                {
                                    "path": next(
                                        callback["registration"]["translation_unit"]
                                        for callback in registration_root["callbacks"]
                                    ),
                                    "line": line,
                                    "column": column,
                                    "macro": is_macro,
                                    "assignments": sorted(
                                        assignments,
                                        key=lambda item: (
                                            item["line"],
                                            item["column"],
                                            item["field"],
                                            item["target"],
                                        ),
                                    ),
                                }
                            )
                            registration_initializer_definitions[root_key][
                                _declaration_key(observed)
                            ] = observed
                except ResolverError as error:
                    command_errors.append(
                        {
                            "command_id": command["id"],
                            "file": _display_path(
                                command["file"], source_root, database_root
                            ),
                            "filter": initializer_filter,
                            "kind": "ast-json",
                            "message": str(error),
                        }
                    )
        for protocol in command_protocols:
            if deadline_exhausted:
                break
            ast_filter = protocol["scope"]["name"]
            if "++" in command["language"]:
                listed = run_frontend(
                    command,
                    ast_filter,
                    _ast_list_command(command, ast_filter),
                    "Clang AST-name",
                )
                if listed is None:
                    continue
                qualified = sorted(
                    {
                        line.strip()
                        for line in listed.stdout.splitlines()
                        if line.strip().endswith("::" + ast_filter)
                    }
                )
                if qualified:
                    command_errors.append(
                        {
                            "command_id": command["id"],
                            "file": _display_path(
                                command["file"], source_root, database_root
                            ),
                            "filter": ast_filter,
                            "kind": "non-global-protocol-scope",
                            "message": "qualified definition(s): {}".format(
                                ", ".join(qualified)
                            ),
                        }
                    )
                    continue

            completed = run_frontend(
                command,
                ast_filter,
                _ast_command(command, ast_filter),
                "Clang AST",
            )
            if completed is None:
                continue
            try:
                source_path = protocol_sources[protocol["scope"]["source"]]
                for root in _json_stream(completed.stdout):
                    for node in _walk_ast(root):
                        observed = _protocol_definition_observation(
                            node,
                            protocol,
                            source_path,
                            command["directory"],
                            contracts_by_id,
                        )
                        if observed is None:
                            continue
                        key = _declaration_key(observed)
                        record = protocol_definitions[protocol["id"]].setdefault(
                            key,
                            {"variants": {}},
                        )
                        variant_key = _canonical_json(observed)
                        variant = record["variants"].setdefault(
                            variant_key,
                            {"definition": observed, "contexts": set()},
                        )
                        variant["contexts"].add(command["id"])
                protocol_analyzed_contexts[protocol["id"]].add(command["id"])
            except ResolverError as error:
                command_errors.append(
                    {
                        "command_id": command["id"],
                        "file": _display_path(
                            command["file"], source_root, database_root
                        ),
                        "filter": ast_filter,
                        "kind": "ast-json",
                        "message": str(error),
                    }
                )
        if deadline_exhausted:
            break

        dependency_file_after = dependency_root / (command["id"] + ".after.d")
        dependencies_after = snapshot_dependencies(
            command, dependency_file_after, "<dependencies-after>"
        )
        if dependencies_after is None:
            continue
        if dependencies_before != dependencies_after:
            before_paths = set(dependencies_before)
            after_paths = set(dependencies_after)
            if before_paths != after_paths:
                detail = "dependency path set changed across AST replay"
            else:
                detail = "dependency contents changed across AST replay"
            command_errors.append(
                {
                    "command_id": command["id"],
                    "file": _display_path(
                        command["file"], source_root, database_root
                    ),
                    "filter": "<dependencies-stability>",
                    "kind": "dependency",
                    "message": detail,
                }
            )
            continue
        if len(set(dependency_snapshots) | set(dependencies_after)) > MAX_DEPENDENCIES:
            command_errors.append(
                {
                    "command_id": command["id"],
                    "file": _display_path(
                        command["file"], source_root, database_root
                    ),
                    "filter": "<dependencies-stability>",
                    "kind": "dependency",
                    "message": "aggregate dependency count exceeds {}".format(
                        MAX_DEPENDENCIES
                    ),
                }
            )
            continue
        for dependency, snapshot in dependencies_after.items():
            _check_deadline(deadline)
            previous = dependency_snapshots.get(dependency)
            if previous is not None and previous != snapshot:
                command_errors.append(
                    {
                        "command_id": command["id"],
                        "file": _display_path(
                            command["file"], source_root, database_root
                        ),
                        "filter": "<dependencies-stability>",
                        "kind": "dependency",
                        "message": "dependency changed between anchor "
                        "compilations: {}".format(
                            _display_path(
                                dependency, source_root, database_root
                            )
                        ),
                    }
                )
                break
            dependency_snapshots[dependency] = snapshot
    dependency_temp.cleanup()

    def member_step_report(step, expected_contexts, step_index):
        key = (step["record_type"], step["header"])
        observed_definitions = []
        for definition_key in sorted(record_definitions.get(key, {})):
            record = record_definitions[key][definition_key]
            if not (record["contexts"] & expected_contexts):
                continue
            definition = record["definition"]
            observed_definitions.append(
                {
                    "path": definition["path"],
                    "line": definition["line"],
                    "column": definition["column"],
                    "sites": [
                        {"line": line, "column": column}
                        for line, column in sorted(record["sites"])
                    ],
                    "fields": definition["fields"],
                    "context_count": len(record["contexts"]),
                    "context_ids": sorted(record["contexts"]),
                }
            )
        if not observed_definitions:
            status = "missing"
        elif len(observed_definitions) > 1:
            status = "ambiguous"
        else:
            observed = observed_definitions[0]
            contexts_match = expected_contexts.issubset(
                set(observed["context_ids"])
            )
            named_fields = [
                field
                for field in observed["fields"]
                if field["name"] == step["field"]
            ]
            field_matches = (
                len(named_fields) == 1
                and _canonical_type(named_fields[0]["type"])
                == _canonical_type(step["type"])
            )
            if not contexts_match:
                status = "missing-context"
            elif not field_matches:
                status = "stale"
            else:
                status = "matched"
        return {
            "step_index": step_index,
            "expected": step,
            "status": status,
            "definitions": observed_definitions,
        }

    contract_reports = []
    for contract in contracts:
        expected = _expected_prototype(contract)
        expected_names = [
            parameter["name"] for parameter in contract["prototype"]["parameters"]
        ]
        observed_records = []
        for key in sorted(declarations[contract["id"]]):
            record = declarations[contract["id"]][key]
            declaration = record["declaration"]
            observed_records.append(
                {
                    "path": declaration["path"],
                    "line": declaration["line"],
                    "column": declaration["column"],
                    "sites": [
                        {"line": line, "column": column}
                        for line, column in sorted(record["sites"])
                    ],
                    "prototype": declaration["prototype"],
                    "parameter_names": declaration["parameter_names"],
                    "parameter_name_variants": [
                        list(names)
                        for names in sorted(record["parameter_name_sets"])
                    ],
                    "variadic": declaration["variadic"],
                    "context_count": len(record["contexts"]),
                    "context_ids": sorted(record["contexts"]),
                }
            )
        if not observed_records:
            status = "missing"
        elif len(observed_records) > 1:
            status = "ambiguous"
        else:
            observed = observed_records[0]
            signature_matches = _canonical_type(observed["prototype"]) == _canonical_type(
                expected
            )
            names_match = expected_names in observed["parameter_name_variants"]
            status = (
                "matched"
                if signature_matches and names_match and not observed["variadic"]
                else "stale"
            )
        expected_contexts = {
            command["id"]
            for command in commands
            if any(
                candidate["id"] == contract["id"]
                for candidate in translation_unit_contracts[command["file"]]
            )
        }
        member_path_reports = []
        for operand in contract_member_operands[contract["id"]]:
            step_reports = [
                member_step_report(step, expected_contexts, step_index)
                for step_index, step in enumerate(operand["path"])
            ]
            member_path_reports.append(
                {
                    "role": operand["role"],
                    "argument_index": operand["index"],
                    "status": (
                        "matched"
                        if all(step["status"] == "matched" for step in step_reports)
                        else "drift"
                    ),
                    "steps": step_reports,
                }
            )
        if status == "matched" and any(
            path["status"] != "matched" for path in member_path_reports
        ):
            status = "member-drift"
        contract_reports.append(
            {
                "contract_id": contract["id"],
                "rule_ids": [contract["rule_id"]]
                + contract.get("additional_rule_ids", []),
                "selector": contract["selector"],
                "expected": {
                    "prototype": expected,
                    "parameter_names": expected_names,
                },
                "status": status,
                "declarations": observed_records,
                "member_paths": member_path_reports,
            }
        )

    callback_reports = []
    for callback in callbacks:
        callback_id = callback["id"]
        slot = callback["slot"]
        registration = callback["registration"]
        slot_contexts = {
            command["id"]
            for command in commands
            if command["file"] == callback_slot_translation_units[callback_id]
        }
        registration_contexts = {
            command["id"]
            for command in commands
            if command["file"]
            == callback_registration_translation_units[callback_id]
        }
        slot_step = {
            "record_type": slot["record_type"],
            "field": slot["field"],
            "type": catalog_tool._function_pointer_type_string(
                callback["prototype"]
            ),
            "header": slot["header"],
        }
        registration_step = {
            "record_type": registration["record_type"],
            "field": registration["field"],
            "type": catalog_tool._function_pointer_type_string(
                registration["prototype"]
            ),
            "header": registration["header"],
        }
        slot_report = member_step_report(slot_step, slot_contexts, 0)
        registration_field_report = member_step_report(
            registration_step, registration_contexts, 0
        )
        root_key = callback_registration_root_keys[callback_id]
        variable_observations = [
            registration_variable_declarations[root_key][key]
            for key in sorted(registration_variable_declarations[root_key])
        ]
        expected_registration_prototype = catalog_tool._prototype_type_string(
            registration["prototype"]
        )
        expected_variable_type = "const {}".format(registration["record_type"])
        if not variable_observations:
            variable_status = "missing"
        elif len(variable_observations) > 1:
            variable_status = "ambiguous"
        else:
            variable = variable_observations[0]
            matching_bindings = [
                binding
                for binding in variable["designated_bindings"]
                if binding["field"] == registration["field"]
            ]
            matching_references = [
                reference
                for reference in variable["function_references"]
                if reference["name"] == registration["initializer"]
            ]
            variable_status = (
                "matched"
                if (
                    _canonical_type(variable["type"])
                    == _canonical_type(expected_variable_type)
                    and matching_bindings
                    == [
                        {
                            "field": registration["field"],
                            "target": registration["initializer"],
                        }
                    ]
                    and len(matching_references) == 1
                    and _canonical_type(matching_references[0]["type"])
                    == _canonical_type(expected_registration_prototype)
                    and not variable["macro"]
                )
                else "stale"
            )
        variable_report = {
            "expected": {
                "name": registration["variable"],
                "type": expected_variable_type,
                "field": registration["field"],
                "target": registration["initializer"],
                "target_prototype": expected_registration_prototype,
            },
            "status": variable_status,
            "declarations": variable_observations,
        }

        initializer_observations = [
            registration_initializer_definitions[root_key][key]
            for key in sorted(registration_initializer_definitions[root_key])
        ]
        expected_initializer_names = [
            parameter["name"]
            for parameter in registration["prototype"]["parameters"]
        ]
        if not initializer_observations:
            initializer_status = "missing"
            assignment_status = "missing"
            matching_assignments = []
        elif len(initializer_observations) > 1:
            initializer_status = "ambiguous"
            assignment_status = "ambiguous"
            matching_assignments = []
        else:
            initializer = initializer_observations[0]
            initializer_status = (
                "matched"
                if (
                    _canonical_type(initializer["prototype"])
                    == _canonical_type(expected_registration_prototype)
                    and initializer["parameter_names"]
                    == expected_initializer_names
                    and not initializer["variadic"]
                    and not initializer["macro"]
                )
                else "stale"
            )
            matching_assignments = [
                assignment
                for assignment in initializer["assignments"]
                if assignment["field"] == slot["field"]
            ]
            expected_slot_pointer_type = catalog_tool._function_pointer_type_string(
                callback["prototype"]
            )
            expected_callback_prototype = catalog_tool._prototype_type_string(
                callback["prototype"]
            )
            if not matching_assignments:
                assignment_status = "missing"
            elif len(matching_assignments) > 1:
                assignment_status = "ambiguous"
            else:
                assignment_status = (
                    "matched"
                    if (
                        _canonical_type(matching_assignments[0]["base_type"])
                        == _canonical_type(slot["record_type"] + " *")
                        and _canonical_type(
                            matching_assignments[0]["member_type"]
                        )
                        == _canonical_type(expected_slot_pointer_type)
                        and matching_assignments[0]["target"]
                        == slot["implementation"]
                        and _canonical_type(
                            matching_assignments[0]["target_type"]
                        )
                        == _canonical_type(expected_callback_prototype)
                        and not matching_assignments[0]["macro"]
                    )
                    else "stale"
                )
        initializer_report = {
            "expected": {
                "name": registration["initializer"],
                "prototype": expected_registration_prototype,
                "parameter_names": expected_initializer_names,
            },
            "status": initializer_status,
            "definitions": initializer_observations,
        }
        assignment_report = {
            "expected": {
                "record_type": slot["record_type"],
                "field": slot["field"],
                "type": catalog_tool._function_pointer_type_string(
                    callback["prototype"]
                ),
                "target": slot["implementation"],
                "target_prototype": catalog_tool._prototype_type_string(
                    callback["prototype"]
                ),
            },
            "status": assignment_status,
            "assignments": matching_assignments,
        }
        registration_report = {
            "expected": registration,
            "status": (
                "matched"
                if (
                    registration_field_report["status"] == "matched"
                    and variable_status == "matched"
                    and initializer_status == "matched"
                    and assignment_status == "matched"
                )
                else "drift"
            ),
            "field": registration_field_report,
            "variable_initializer": variable_report,
            "class_initializer": initializer_report,
            "slot_assignment": assignment_report,
        }
        entry_input_reports = []
        for entry_input in sorted(
            callback["entry_inputs"], key=lambda item: item["role"]
        ):
            step_reports = [
                member_step_report(step, slot_contexts, step_index)
                for step_index, step in enumerate(entry_input.get("path", []))
            ]
            entry_input_reports.append(
                {
                    "role": entry_input["role"],
                    "source": entry_input["source"],
                    "argument_index": entry_input["index"],
                    "status": (
                        "matched"
                        if all(step["status"] == "matched" for step in step_reports)
                        else "drift"
                    ),
                    "steps": step_reports,
                }
            )
        entry_reports_by_role = {
            entry_input["role"]: entry_input
            for entry_input in entry_input_reports
        }
        entry_sources_by_role = {
            entry_input["role"]: entry_input
            for entry_input in callback["entry_inputs"]
        }
        input_buffer_reports = []
        for input_buffer in sorted(
            callback["input_buffers"], key=lambda item: item["buffer_index"]
        ):
            length_role = input_buffer["length_role"]
            selector_role = input_buffer["active_when"]["role"]
            length_input = entry_sources_by_role[length_role]
            selector_input = entry_sources_by_role[selector_role]
            input_buffer_reports.append(
                {
                    "expected": input_buffer,
                    "buffer_argument_index": input_buffer["buffer_index"],
                    "buffer_type": callback["prototype"]["parameters"][
                        input_buffer["buffer_index"]
                    ]["type"],
                    "length_role": length_role,
                    "length_argument_index": length_input["index"],
                    "selector_role": selector_role,
                    "selector_argument_index": selector_input["index"],
                    "status": (
                        "matched"
                        if (
                            slot_report["status"] == "matched"
                            and entry_reports_by_role[length_role]["status"]
                            == "matched"
                            and entry_reports_by_role[selector_role]["status"]
                            == "matched"
                        )
                        else "drift"
                    ),
                }
            )
        if slot_report["status"] != "matched":
            status = "slot-drift"
        elif registration_report["status"] != "matched":
            status = "registration-drift"
        elif any(
            entry_input["status"] != "matched"
            for entry_input in entry_input_reports
        ):
            status = "member-drift"
        elif any(
            input_buffer["status"] != "matched"
            for input_buffer in input_buffer_reports
        ):
            status = "input-buffer-drift"
        else:
            status = "matched"
        callback_reports.append(
            {
                "binding_id": callback_id,
                "rule_ids": callback["rule_ids"],
                "family": callback["family"],
                "expected": {
                    "prototype": catalog_tool._prototype_type_string(
                        callback["prototype"]
                    ),
                    "slot": slot,
                    "registration": registration,
                    "entry_inputs": callback["entry_inputs"],
                    "input_buffers": callback["input_buffers"],
                },
                "status": status,
                "slot": slot_report,
                "registration_root": registration_report,
                "entry_inputs": entry_input_reports,
                "input_buffers": input_buffer_reports,
            }
        )

    protocol_reports = []
    for protocol in protocols:
        scope = protocol["scope"]
        expected_prototype = _expected_prototype(scope)
        expected_names = [
            parameter["name"] for parameter in scope["prototype"]["parameters"]
        ]
        analyzed_contexts = protocol_analyzed_contexts[protocol["id"]]
        observed_definitions = []
        for key in sorted(protocol_definitions[protocol["id"]]):
            record = protocol_definitions[protocol["id"]][key]
            context_variants = []
            all_contexts = set()
            for variant_key in sorted(record["variants"]):
                variant = record["variants"][variant_key]
                variant_observation = dict(variant["definition"])
                variant_observation["context_count"] = len(variant["contexts"])
                variant_observation["context_ids"] = sorted(variant["contexts"])
                context_variants.append(variant_observation)
                all_contexts.update(variant["contexts"])
            observed = dict(context_variants[0])
            observed["context_count"] = len(all_contexts)
            observed["context_ids"] = sorted(all_contexts)
            observed["context_variant_count"] = len(context_variants)
            observed["context_variants"] = context_variants
            observed_definitions.append(observed)
        if not observed_definitions:
            status = "missing"
        elif len(observed_definitions) > 1:
            status = "ambiguous"
        else:
            observed = observed_definitions[0]
            contexts_match = observed["context_variant_count"] == 1
            context_coverage_matches = (
                set(observed["context_ids"]) == analyzed_contexts
            )
            scope_matches = (
                _canonical_type(observed["prototype"])
                == _canonical_type(expected_prototype)
                and observed["parameter_names"] == expected_names
                and not observed["variadic"]
            )
            events_match = all(
                event["status"] == "matched" for event in observed["events"]
            )
            if not context_coverage_matches:
                status = "missing-context"
            elif not contexts_match:
                status = "context-drift"
            elif not scope_matches:
                status = "stale"
            elif not events_match:
                status = "event-drift"
            else:
                status = "matched"
        protocol_reports.append(
            {
                "protocol_id": protocol["id"],
                "scope": scope,
                "expected": {
                    "prototype": expected_prototype,
                    "parameter_names": expected_names,
                    "events": protocol["events"],
                },
                "analyzed_context_count": len(analyzed_contexts),
                "analyzed_context_ids": sorted(analyzed_contexts),
                "status": status,
                "definitions": observed_definitions,
            }
        )

    def append_changed(path, snapshot, display, message):
        try:
            changed = (
                _file_snapshot(
                    path,
                    with_hash=True,
                    budget=attestation_budget,
                    deadline=deadline,
                )
                != snapshot
            )
        except _DeadlineExceeded:
            raise
        except ResolverError:
            changed = True
        if changed:
            command_errors.append(
                {
                    "command_id": "",
                    "file": display,
                    "filter": "",
                    "kind": "input-changed",
                    "message": message,
                }
            )

    append_changed(
        compile_commands_path,
        database_snapshot,
        "$COMPILE_DATABASE_DIR/" + compile_commands_path.name,
        "compile_commands.json changed during resolution",
    )
    append_changed(
        resolver_path,
        resolver_snapshot,
        "$RESOLVER/qemu_contract_catalog_resolver.py",
        "catalog resolver changed during resolution",
    )
    append_changed(
        generator_path,
        generator_snapshot,
        "$RESOLVER/qemu_contract_catalog.py",
        "catalog generator changed during resolution",
    )
    for name, header in sorted(headers.items()):
        append_changed(
            header,
            header_snapshots[name],
            "$SOURCE_ROOT/" + name,
            "catalog-declared header changed during resolution",
        )
    for name, source in sorted(protocol_sources.items()):
        append_changed(
            source,
            protocol_source_snapshots[name],
            "$SOURCE_ROOT/" + name,
            "protocol scope source changed during resolution",
        )
    for source, snapshot in sorted(
        source_snapshots.items(), key=lambda item: item[0].as_posix()
    ):
        append_changed(
            source,
            snapshot,
            _display_path(source, source_root, database_root),
            "anchor translation unit changed during resolution",
        )
    primary_inputs = (
        set(headers.values()) | set(protocol_sources.values()) | set(source_snapshots)
    )
    for dependency, snapshot in sorted(
        dependency_snapshots.items(), key=lambda item: item[0].as_posix()
    ):
        if dependency in primary_inputs:
            continue
        append_changed(
            dependency,
            snapshot,
            _display_path(dependency, source_root, database_root),
            "compiler dependency changed during resolution",
        )
    for invocation, snapshot in sorted(
        compiler_invocation_snapshots.items(), key=lambda item: item[0].as_posix()
    ):
        append_changed(
            invocation,
            snapshot,
            _display_path(invocation, source_root, database_root),
            "Clang compiler invocation changed during resolution",
        )
    for target, snapshot in sorted(
        compiler_snapshots.items(), key=lambda item: item[0].as_posix()
    ):
        append_changed(
            target,
            snapshot,
            _display_path(target, source_root, database_root),
            "Clang compiler changed during resolution",
        )
    for invocation, snapshot in sorted(
        frontend_invocation_snapshots.items(),
        key=lambda item: item[0].as_posix(),
    ):
        append_changed(
            invocation,
            snapshot,
            _display_path(invocation, source_root, database_root),
            "Clang -cc1 job invocation changed during resolution",
        )
    for target, snapshot in sorted(
        frontend_snapshots.items(), key=lambda item: item[0].as_posix()
    ):
        append_changed(
            target,
            snapshot,
            _display_path(target, source_root, database_root),
            "Clang -cc1 job executable changed during resolution",
        )

    if time.monotonic() >= deadline and not deadline_exhausted:
        command_errors.append(
            {
                "command_id": "",
                "file": "",
                "filter": "",
                "kind": "global-timeout",
                "message": "source-drift resolution exceeded {} seconds".format(
                    timeout_seconds
                ),
            }
        )

    command_errors.sort(
        key=lambda error: (
            error["command_id"],
            error["filter"],
            error["kind"],
            error.get("message", ""),
        )
    )
    if command_errors:
        result = "error"
    elif all(
        contract["status"] == "matched" for contract in contract_reports
    ) and all(
        callback["status"] == "matched" for callback in callback_reports
    ) and all(protocol["status"] == "matched" for protocol in protocol_reports):
        result = "pass"
    else:
        result = "drift"

    normalized_commands = [
        {
            "id": command["id"],
            "directory": _display_path(command["directory"], source_root, database_root),
            "file": _display_path(command["file"], source_root, database_root),
            "language": command["language"],
            "compiler_sha256": command["compiler"]["sha256"],
            "cc1_executable_sha256": command["cc1_executable"]["sha256"],
            "driver_plan_sha256": command["driver_plan_sha256"],
            "cc1_replay_plan_sha256": command["cc1_replay_plan_sha256"],
            "selectors": sorted(
                [
                    contract["selector"]["name"]
                    for contract in translation_unit_contracts[command["file"]]
                ]
                + [
                    protocol["scope"]["name"]
                    for protocol in translation_unit_protocols[command["file"]]
                ]
                + [
                    record["record_type"]
                    for record in translation_unit_member_records[
                        command["file"]
                    ].values()
                ]
                + [
                    name
                    for root in registration_roots.values()
                    if root["translation_unit"] == command["file"]
                    for name in (root["variable"], root["initializer"])
                ]
            ),
        }
        for command in sorted(commands, key=lambda item: item["file"].as_posix())
    ]
    compilers = {
        _canonical_json(command["compiler"]): command["compiler"]
        for command in commands
    }
    frontends = {
        _canonical_json(command["cc1_executable"]): command["cc1_executable"]
        for command in commands
    }
    dependency_manifest = [
        {
            "path": _display_path(path, source_root, database_root),
            "bytes": snapshot["bytes"],
            "sha256": snapshot["sha256"],
        }
        for path, snapshot in sorted(
            dependency_snapshots.items(), key=lambda item: item[0].as_posix()
        )
    ]
    report = {
        "report_format": REPORT_FORMAT,
        "kind": "qemu-contract-source-drift",
        "result": result,
        "tool": {
            "resolver_sha256": resolver_snapshot["sha256"],
            "catalog_generator_sha256": generator_snapshot["sha256"],
        },
        "scope": {
            "kind": "catalog-anchored-compilation-database-replay",
            "coverage_attestation": "external-required",
            "claim": "selector-member-callback-binding-and-protocol-source-drift-only",
            "max_ast_runs": MAX_AST_RUNS,
            "max_ast_output_bytes": MAX_AST_OUTPUT_BYTES,
            "max_compile_database_bytes": MAX_COMPILE_DATABASE_BYTES,
            "max_compile_commands": MAX_COMPILE_COMMANDS,
            "max_dependency_file_bytes": MAX_DEPENDENCY_FILE_BYTES,
            "max_dependencies": MAX_DEPENDENCIES,
            "max_attested_file_bytes": MAX_ATTESTED_FILE_BYTES,
            "max_aggregate_attested_bytes": MAX_AGGREGATE_ATTESTED_BYTES,
            "aggregate_attested_bytes": attestation_budget.total,
            "global_timeout_seconds": timeout_seconds,
        },
        "catalog": {
            "format": catalog["catalog_format"],
            "model_version": catalog["model_version"],
            "sha256": catalog_tool._sha256(catalog_tool._normalized_catalog(catalog)),
            "schema_sha256": catalog_tool._sha256(schema),
        },
        "source": {
            "root": "$SOURCE_ROOT",
            "headers": [
                {
                    "path": name,
                    "bytes": header_snapshots[name]["bytes"],
                    "sha256": header_snapshots[name]["sha256"],
                }
                for name in sorted(headers)
            ],
            "protocol_sources": [
                {
                    "path": name,
                    "bytes": protocol_source_snapshots[name]["bytes"],
                    "sha256": protocol_source_snapshots[name]["sha256"],
                }
                for name in sorted(protocol_sources)
            ],
            "translation_units": [
                {
                    "path": name,
                    "bytes": source_snapshots[path]["bytes"],
                    "sha256": source_snapshots[path]["sha256"],
                }
                for name, path in sorted(translation_units.items())
            ],
            "dependency_count": len(dependency_manifest),
            "dependency_manifest_sha256": _value_hash(dependency_manifest),
            "dependencies": dependency_manifest,
        },
        "environment": {
            "semantic": semantic_environment,
            "sha256": _value_hash(semantic_environment),
        },
        "compilers": [compilers[key] for key in sorted(compilers)],
        "cc1_executables": [
            frontends[key] for key in sorted(frontends)
        ],
        "compile_database": {
            "path": "$COMPILE_DATABASE_DIR/" + compile_commands_path.name,
            "sha256": database_snapshot["sha256"],
            "entry_count": raw_command_count,
            "unique_command_count": len(all_commands),
            "anchor_command_count": len(commands),
            "ast_run_count": run_count,
            "callback_binding_count": len(callbacks),
            "protocol_count": len(protocols),
            "commands_sha256": _value_hash(normalized_commands),
            "commands": normalized_commands,
            "selector_filters": filters,
        },
        "contracts": contract_reports,
        "callback_bindings": callback_reports,
        "protocols": protocol_reports,
        "errors": command_errors,
    }
    _check_deadline(deadline)
    return report


def _write_report(report, output):
    serialized = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if str(output) == "-":
        sys.stdout.write(serialized)
        return
    try:
        Path(output).write_text(serialized, encoding="utf-8")
    except OSError as error:
        raise ResolverError("{}: {}".format(output, error)) from error


def _default_paths():
    clang_root = Path(__file__).resolve().parents[2]
    checker_dir = clang_root / "lib" / "StaticAnalyzer" / "Checkers"
    return (
        checker_dir / "QEMUContractCatalog.json",
        checker_dir / "QEMUContractCatalog.schema.json",
    )


def main(argv=None):
    default_catalog, default_schema = _default_paths()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=default_catalog)
    parser.add_argument("--schema", type=Path, default=default_schema)
    parser.add_argument("--compile-commands", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("-"))
    parser.add_argument(
        "--timeout-seconds", type=int, default=DEFAULT_TIMEOUT_SECONDS
    )
    arguments = parser.parse_args(argv)
    try:
        catalog = catalog_tool.load_json_strict(arguments.catalog)
        schema = catalog_tool.load_json_strict(arguments.schema)
        report = resolve_catalog(
            catalog,
            schema,
            arguments.compile_commands,
            arguments.source_root,
            arguments.timeout_seconds,
        )
        _write_report(report, arguments.output)
        if report["result"] == "pass":
            return 0
        return 1 if report["result"] == "drift" else 2
    except (catalog_tool.CatalogError, ResolverError) as error:
        report = {
            "report_format": REPORT_FORMAT,
            "kind": "qemu-contract-source-drift",
            "result": "error",
            "errors": [{"kind": "input", "message": str(error)}],
        }
        try:
            _write_report(report, arguments.output)
        except ResolverError as output_error:
            print("error: {}".format(output_error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
