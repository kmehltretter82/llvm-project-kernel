#!/usr/bin/env python3
"""Serial RISC-V port of the frozen manifest campaign."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shutil
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent
MODEL = "linux-rt-context-1"
PROFILES = ["riscv64-nonrt", "riscv64-rt-bh-y", "riscv64-rt-bh-n"]
FUNCTION_FIELDS = ["name", "type", "linkage", "source_path", "source_sha256", "offset"]
ADDRESS_SPACE_LIMIT_MIB = None if sys.platform == "darwin" else 3072


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def verify(pins):
    changed = [name for name, value in pins.items() if sha(name) != value]
    if changed:
        raise RuntimeError("Input drift: " + repr(changed))


def execute(argv, cwd, env):
    def limits():
        if ADDRESS_SPACE_LIMIT_MIB is not None:
            space = ADDRESS_SPACE_LIMIT_MIB * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (space, space))
        resource.setrlimit(resource.RLIMIT_CPU, (120, 122))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    save(cwd / "command.json", {"argv": argv, "cwd": str(cwd)})
    start = time.monotonic()
    timeout = kill = False
    with (cwd / "stdout.log").open("wb") as out, (cwd / "stderr.log").open("wb") as err:
        p = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                             stdout=out, stderr=err, start_new_session=True, preexec_fn=limits)
        while True:
            pid, status, usage = os.wait4(p.pid, os.WNOHANG)
            if pid:
                p.returncode = os.waitstatus_to_exitcode(status)
                break
            elapsed = time.monotonic() - start
            if elapsed >= 120 and not timeout:
                timeout = True
                try:
                    os.killpg(p.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            if elapsed >= 122 and not kill:
                kill = True
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            time.sleep(0.05)
    output = (cwd / "stdout.log").read_text(errors="replace") + (cwd / "stderr.log").read_text(errors="replace")
    diagnostic = cwd / "diagnostics.txt"
    if diagnostic.exists():
        output += diagnostic.read_text(errors="replace")
    warnings = list(dict.fromkeys(line for line in output.splitlines() if "warning:" in line))
    messages = {
        warning: warning.split("warning:", 1)[1].rsplit(" [", 1)[0]
        for warning in warnings
    }
    stats = [{"value": int(m[1]), "component": m[2], "description": m[3]}
             for m in re.finditer(r"^\s*(\d+)\s+(AnalysisConsumer|CoreEngine|ExprEngine)\s+-\s+(.*)$", output, re.M)]
    bounds = [s for s in stats if s["value"] and
              re.search(r"max number of steps|maximum block count|without inlining", s["description"])]
    validation = [w for w in warnings
                  if re.search(r"manifest", messages[w], re.I)]
    gaps = [w for w in warnings if w not in validation and
            (re.search(r"unknown|incomplete", messages[w], re.I) or
             "no proved post-call context preservation" in messages[w])]
    waits = [w for w in warnings if w not in validation + gaps and
             re.search(r"RT lock|RT.?wait|rt-lock-wait", messages[w], re.I)]
    sleeps = [w for w in warnings if w not in validation + gaps + waits and
              re.search(r"sleep|blocking", messages[w], re.I)]
    unexpected = [w for w in warnings
                  if w not in validation + gaps + waits + sleeps]
    max_rss_kib = (usage.ru_maxrss // 1024
                   if sys.platform == "darwin" else usage.ru_maxrss)
    result = {"exit_code": p.returncode, "timeout": timeout, "forced_sigkill": kill,
              "wall_seconds": round(time.monotonic() - start, 4), "max_rss_kib": max_rss_kib,
              "user_seconds": usage.ru_utime, "system_seconds": usage.ru_stime,
              "address_space_limit_mib": ADDRESS_SPACE_LIMIT_MIB,
              "address_space_limit_note":
                  ("RLIMIT_AS is not usable for the macOS VM layout"
                   if ADDRESS_SPACE_LIMIT_MIB is None else "enforced"),
              "wall_limit_seconds": 120,
              "cpu_soft_limit_seconds": 120, "cpu_hard_limit_seconds": 122,
              "warnings": warnings, "rt_wait_warnings": waits, "ordinary_sleep_warnings": sleeps,
              "manifest_validation_warnings": validation,
              "incomplete_context_warnings": gaps,
              "unexpected_warnings": unexpected,
              "analyzer_statistics": stats, "bounds": bounds,
              "analysis_observed": any(s["component"] == "CoreEngine" and s["value"] > 0 and
                                       "paths explored" in s["description"] for s in stats),
              "allocation_failure": bool(re.search(r"out of memory|cannot allocate memory|bad_alloc", output, re.I))}
    result["process_and_analysis_completed"] = (p.returncode == 0 and not timeout and not bounds and
                                                not result["allocation_failure"] and result["analysis_observed"])
    save(cwd / "PROCESS.json", result)
    return result


def command(compiler, triple, source, function, directory, option):
    config = ("alpha.linux.AtomicSleep:RTContext=true,"
              "alpha.linux.KernelModel:SkipIrrelevant=false,"
              "alpha.linux.KernelModel:LikelyStaticBranches=false,max-nodes=225000")
    if option:
        config += "," + option
    return [str(compiler), "-cc1", "-triple", triple, "-x", "c", "-std=gnu11",
            "-analyze", "-analyzer-checker=core,alpha.linux.AtomicSleep,alpha.linux.LockBalance",
            "-analyzer-config", config, "-analyzer-output=text", "-analyzer-stats", "-print-stats",
            "-stats-file=" + str(directory / "statistics.json"), "-analyzer-max-loop", "4",
            "-analyze-function=" + function, "-o", str(directory / "diagnostics.txt"), str(source)]


def binding(facts, name, source):
    records = [f for f in facts["functions"] if f["name"] == name and
               Path(f["source_path"]).resolve() == source.resolve()]
    if len(records) != 1:
        raise RuntimeError("Ambiguous/missing captured function binding: " + name + ": " + repr(records))
    return {field: records[0][field] for field in FUNCTION_FIELDS}


def manifest(case, facts, inputs, evidence):
    source = inputs / case["source"]
    base = {key: facts[key] for key in ["target_triple", "translation_unit", "files", "macros", "predefines_sha256"]}
    base["files"] = dict(base["files"])
    base.update({"schema": 1, "effect_model": MODEL,
                 "configuration": {"kind": case.get("configuration_kind", "api-fixture")}, "functions": []})
    for path in [inputs / ".config", inputs / "external-effect-definitions.c", evidence]:
        base["files"][str(path.resolve())] = sha(path)
    if base["configuration"]["kind"] == "kernel":
        base["configuration"].update({"config_path": str(inputs / ".config"),
                                      "autoconf_path": str(inputs / "generated/autoconf.h")})
    review = {"path": str(evidence), "sha256": sha(evidence)}

    def entry(name, context, captured=facts, entry_source=source):
        record = binding(captured, name, entry_source)
        record.update({"kind": "entry", "context": context, "evidence": review})
        base["functions"].append(record)

    entry(case["function"], case["context"])
    if "additional_entry" in case:
        other = case["additional_entry"]
        entry(other["function"], other["context"])
    if "foreign_other_tu_entry_context" in case:
        other_source = inputs / case["same_name_other_tu"]
        other_facts = json.loads((inputs.parent / "facts" / case["same_name_other_tu"] / "facts.json").read_text())
        base["files"][str(other_source)] = sha(other_source)
        entry(case["function"], case["foreign_other_tu_entry_context"], other_facts, other_source)
    name = {"rt-lock-wait": "p3_rt_wait_effect", "ordinary-sleep": "p3_ordinary_sleep_effect",
            "unknown": "p3_opaque_effect"}[case["effect"]]
    effect = binding(facts, name, source)
    effect.update({"kind": "effect", "effect": case["effect"], "evidence": review})
    base["functions"].append(effect)
    if case.get("unknown_effect_also_required"):
        effect = binding(facts, "p3_opaque_effect", source)
        effect.update({"kind": "effect", "effect": "unknown", "evidence": review})
        base["functions"].append(effect)
    mutation = case["manifest_mutation"]
    if mutation == "tu_hash":
        base["translation_unit"] = dict(base["translation_unit"], sha256="0" * 64)
    elif mutation == "evidence_hash":
        base["functions"][0]["evidence"] = dict(review, sha256="0" * 64)
    elif mutation in ["header_hash", "config_hash", "autoconf_hash"]:
        name = {"header_hash": "fixture-context.h", "config_hash": ".config", "autoconf_hash": "generated/autoconf.h"}[mutation]
        base["files"][str(inputs / name)] = "0" * 64
    elif mutation == "target_triple":
        base["target_triple"] = "aarch64-unknown-linux-gnu" if "x86_64" in base["target_triple"] else "x86_64-unknown-linux-gnu"
    elif mutation == "conflicting_record":
        base["functions"].append(dict(base["functions"][-1], effect="ordinary-sleep"))
    return base


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--compiler", type=Path)
    parser.add_argument("--compiler-sha256")
    parser.add_argument("--compiler-manifest", type=Path)
    parser.add_argument("--output", default="riscv-prepared-v1")
    parser.add_argument("--profiles", nargs="+", choices=PROFILES, default=PROFILES)
    parser.add_argument("--cases", nargs="+")
    args = parser.parse_args()
    output = (ROOT / args.output).resolve()
    assert output.is_relative_to(ROOT) and output != ROOT
    output.mkdir(exist_ok=False)
    oracle = json.loads((ROOT / "EXPECTED.json").read_text())
    supplement = json.loads((ROOT / "COVERAGE-SEMANTICS-SUPPLEMENT.json").read_text())
    freeze = json.loads((ROOT / "ORACLE-FREEZE.json").read_text())
    oracle_pins = {str(ROOT / name): h for name, h in freeze["file_sha256"].items()}
    oracle_pins.update({str(ROOT / name): sha(ROOT / name) for name in
                        ["ORACLE-FREEZE.json", "COVERAGE-SEMANTICS-SUPPLEMENT.json",
                         "COVERAGE-SEMANTICS-SUPPLEMENT.txt", "run.py",
                         "run-riscv.py"]})
    verify(oracle_pins)
    assert supplement["original_oracle_sha256"] == sha(ROOT / "EXPECTED.json")
    cases = [c for c in oracle["cases"] if not args.cases or c["id"] in args.cases]
    assert cases and (not args.cases or len(cases) == len(set(args.cases)))
    save(output / "PLAN.json", {"created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
         "profiles": args.profiles, "cases": [c["id"] for c in cases], "records": len(cases) * len(args.profiles),
         "facts_output_used_only_for_actual_identity_not_expected_semantics": True,
         "frozen_oracle_pins": oracle_pins, "new_compiler_run_requested": args.run})
    if not args.run:
        print("Prepared " + str(len(cases) * len(args.profiles)) + " independent profile records; no compiler executed.")
        return 0
    assert args.compiler and args.compiler_sha256 and args.compiler_manifest
    compiler = args.compiler.resolve(strict=True)
    assert sha(compiler) == args.compiler_sha256
    (output / "tmp").mkdir()
    env = dict(os.environ, LC_ALL="C", TMPDIR=str(output / "tmp"))
    for key in ["CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "CCC_OVERRIDE_OPTIONS"]:
        env.pop(key, None)
    resource_dir = Path(subprocess.check_output([str(compiler), "--print-resource-dir"], env=env).decode().strip())
    assert resource_dir.is_dir()
    common = dict(oracle_pins)
    common[str(compiler)] = args.compiler_sha256
    common[str(args.compiler_manifest.resolve())] = sha(args.compiler_manifest)
    common.update({str(p): sha(p) for p in resource_dir.rglob("*") if p.is_file()})
    records = []
    for profile in args.profiles:
        directory = output / profile
        directory.mkdir()
        inputs = directory / "inputs"
        inputs.mkdir()
        for name in ["fixture_cases.c", "same_static_a.c", "same_static_b.c", "fixture-context.h", "external-effect-definitions.c"]:
            shutil.copyfile(ROOT / name, inputs / name)
        (inputs / "generated").mkdir()
        defines = {"CONFIG_PREEMPT_RT": "1" if "-rt-" in profile else "absent",
                   "CONFIG_PREEMPT_RT_NEEDS_BH_LOCK": "1" if "-rt-bh-y" in profile else "absent"}
        (inputs / "generated/autoconf.h").write_text("".join("#define " + k + " " + v + "\n" for k, v in defines.items() if v != "absent"))
        (inputs / ".config").write_text("# Synthetic API-fixture configuration; not resolved Kconfig\n" +
                                       "".join(k + "=y\n" if v != "absent" else "# " + k + " is not set\n" for k, v in defines.items()))
        pins = dict(common)
        pins.update({str(p): sha(p) for p in inputs.rglob("*") if p.is_file()})
        save(directory / "inputs-before.json", pins)
        triple = "riscv64-unknown-linux-gnu"
        sources = list(dict.fromkeys([c["source"] for c in cases] + [c["same_name_other_tu"] for c in cases if "foreign_other_tu_entry_context" in c]))
        for source in sources:
            fact_dir = directory / "facts" / source
            fact_dir.mkdir(parents=True)
            focus = "p3_case_task_wait" if source == "fixture_cases.c" else "p3_same_entry"
            argv = command(compiler, triple, inputs / source, focus, fact_dir,
                           "alpha.linux.AtomicSleep:RTContextManifestOutput=" + str(fact_dir / "facts.json"))
            verify(pins)
            result = execute(argv, fact_dir, env)
            verify(pins)
            assert result["process_and_analysis_completed"] and (fact_dir / "facts.json").is_file(), "Identity capture failed"
        for case in cases:
            run_dir = directory / case["id"]
            run_dir.mkdir()
            facts_path = directory / "facts" / case["source"] / "facts.json"
            facts = json.loads(facts_path.read_text())
            case_pins = dict(pins)
            case_pins[str(facts_path)] = sha(facts_path)
            option = ""
            if case.get("manifest_enabled", True):
                value = manifest(case, facts, inputs, ROOT / "REVIEW-EVIDENCE.txt")
                text = json.dumps(value, indent=2, sort_keys=True) + "\n"
                if case["manifest_mutation"] == "duplicate_key":
                    text = text.replace('{\n', '{\n  "target_triple": "duplicated-untrusted-key",\n', 1)
                (run_dir / "manifest.json").write_text(text)
                option = "alpha.linux.AtomicSleep:RTContextManifest=" + str(run_dir / "manifest.json")
                case_pins[str(run_dir / "manifest.json")] = sha(run_dir / "manifest.json")
            save(run_dir / "inputs-before.json", case_pins)
            argv = command(compiler, triple, inputs / case["source"], case["function"], run_dir, option)
            verify(case_pins)
            result = execute(argv, run_dir, env)
            verify(case_pins)
            save(run_dir / "inputs-after.json", {p: sha(p) for p in case_pins})
            oracle_profile = profile.replace("riscv64-", "arm64-", 1)
            expected = case["expected"][oracle_profile]
            operation_matches = (bool(result["rt_wait_warnings"]) == expected["rt_lock_wait_warning"] and
                                 bool(result["ordinary_sleep_warnings"]) == expected["ordinary_sleep_warning"])
            if case.get("required_rt_warning_call_index") == 0 and expected["rt_lock_wait_warning"]:
                source_text = (inputs / case["source"]).read_text()
                body = source_text.index("{", source_text.index(case["function"]))
                call = source_text.index("p3_rt_wait_effect", body)
                line = source_text[:call].count("\n") + 1
                operation_matches &= any(":" + str(line) + ":" in w for w in result["rt_wait_warnings"])
            validation_case = case["manifest_mutation"] is not None
            validation_matches = bool(result["manifest_validation_warnings"]) == validation_case
            base_ok = (result["process_and_analysis_completed"] and
                       not result["unexpected_warnings"] and operation_matches and
                       validation_matches)
            raw = base_ok and bool(result["incomplete_context_warnings"]) == expected["incomplete_context_warning"]
            overlay = supplement["case_overlays"][case["id"]]
            if validation_case:
                reviewed = base_ok and not result["incomplete_context_warnings"]
            else:
                reviewed = (base_ok and
                            bool(result["incomplete_context_warnings"]) ==
                            overlay["required_incomplete_context_warning"])
            record = {"profile": profile, "oracle_profile": oracle_profile,
                      "case": case["id"], "expected_original": expected,
                      "coverage_supplement": overlay, "original_raw_predicate_verdict": raw,
                      "manifest_validation_case": validation_case,
                      "manifest_validation_predicate_verdict": validation_matches,
                      "reviewed_supported_operation_predicate_verdict": reviewed,
                      "complete_coverage": overlay["complete_coverage"] and reviewed,
                      "result": result}
            save(run_dir / "VERDICT.json", record)
            records.append(record)
        save(directory / "inputs-after.json", {p: sha(p) for p in pins})
        print(profile + ": evaluated " + str(len(cases)) + " cases", flush=True)
    save(output / "RESULTS.json", {"records": records,
         "original_raw_qualification": bool(records) and all(r["original_raw_predicate_verdict"] for r in records),
         "reviewed_supported_operation_predicates": bool(records) and all(r["reviewed_supported_operation_predicate_verdict"] for r in records),
         "complete_coverage": bool(records) and all(r["complete_coverage"] for r in records),
         "compiler_sha256_before": args.compiler_sha256, "compiler_sha256_after": sha(compiler),
         "kernel_verdict": "not established; these are API fixtures"})
    return 0 if records and all(r["reviewed_supported_operation_predicate_verdict"] for r in records) else 1


if __name__ == "__main__":
    raise SystemExit(main())
