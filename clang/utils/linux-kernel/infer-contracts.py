#!/usr/bin/env python3
"""Turn the facts of a kernel build into a contracts file.

A build with -flinux-kernel-emit-facts=<file> appends one line for every
function that other translation units can call:

    fn <name> <file> <return sources> <functions it always calls>

This script closes those facts over the whole build and writes what the
second build reads with -flinux-kernel-contracts=<file>:

    err_ptr <name>    returns ERR_PTR() on failure and never NULL
    null    <name>    returns NULL on failure and never ERR_PTR()
    sleeps  <name>    sleeps whenever it runs to its end

The return sources are letters: E (ERR_PTR), e (the result of an error
pointer function), N (NULL), n (the untested result of a function that
returns NULL on failure), V (valid), M (read from memory), O (opaque).
",c:<name>" follows for a function of another translation unit whose result
is returned, ",k:<name>" if that result was tested for NULL first.

usage: infer-contracts.py [-o contracts] [--explain name] facts...
"""
import argparse
import collections
import sys

# Functions that sleep by definition: the same list as classify() in
# clang/lib/StaticAnalyzer/Checkers/LinuxAtomicSleepChecker.cpp.
SLEEPS = {
    "__might_sleep",
    "schedule", "schedule_timeout", "schedule_timeout_interruptible",
    "schedule_timeout_killable", "schedule_timeout_uninterruptible",
    "schedule_timeout_idle", "schedule_hrtimeout", "schedule_hrtimeout_range",
    "io_schedule", "io_schedule_timeout",
    "msleep", "msleep_interruptible", "usleep_range_state",
    "mutex_lock", "mutex_lock_nested", "mutex_lock_interruptible",
    "mutex_lock_interruptible_nested", "mutex_lock_killable",
    "mutex_lock_killable_nested", "mutex_lock_io", "mutex_lock_io_nested",
    "_mutex_lock_nest_lock",
    "down", "down_interruptible", "down_killable", "down_timeout",
    "down_read", "down_read_nested", "down_read_interruptible",
    "down_read_killable", "down_write", "down_write_nested",
    "down_write_killable", "down_write_killable_nested",
    "wait_for_completion", "wait_for_completion_timeout",
    "wait_for_completion_interruptible",
    "wait_for_completion_interruptible_timeout",
    "wait_for_completion_killable", "wait_for_completion_killable_timeout",
    "wait_for_completion_io", "wait_for_completion_io_timeout",
    "wait_for_completion_state",
    "synchronize_rcu", "synchronize_rcu_expedited", "synchronize_srcu",
    "synchronize_net", "synchronize_irq", "rcu_barrier",
    "flush_work", "flush_delayed_work", "cancel_work_sync",
    "cancel_delayed_work_sync", "__flush_workqueue", "drain_workqueue",
    "destroy_workqueue",
    "kthread_stop", "free_irq", "devm_free_irq", "disable_irq",
    "vmalloc_noprof", "vzalloc_noprof",
}


def parse(paths):
    """name -> list of (file, flags, [(callee, checked)], calls) per definition."""
    defs = collections.defaultdict(list)
    seen = set()
    for path in paths:
        with open(path, errors="replace") as f:
            for line in f:
                if line in seen:
                    continue
                seen.add(line)
                parts = line.rstrip("\n").split("\t")
                if len(parts) != 5 or parts[0] != "fn":
                    continue
                _, name, file, returns, calls = parts
                flags, callees = None, []
                if returns != "-":
                    first, *rest = returns.split(",")
                    flags = set(first) if first[:2] not in ("c:", "k:") else set()
                    if first[:2] in ("c:", "k:"):
                        rest = [first] + rest
                    for token in rest:
                        callees.append((token[2:], token[0] == "k"))
                always = [] if calls == "-" else calls.split(",")
                defs[name].append((file, flags, callees, always))
    return defs


UNKNOWN, ERR, NULL = "unknown", "err_ptr", "null"


def classify(flags):
    err = "E" in flags or "e" in flags
    null = "N" in flags or "n" in flags
    if err and not null and "M" not in flags and "O" not in flags \
            and ("V" in flags or "e" in flags):
        return ERR
    if null and not err and "O" not in flags \
            and (flags & set("VMn")):
        return NULL
    return UNKNOWN


def conventions(defs):
    """Fixed point over the functions whose result comes from other units."""
    result = {}
    pending = {}
    for name, entries in defs.items():
        entries = [e for e in entries if e[1] is not None]
        if not entries:
            continue
        if not any(e[2] for e in entries):
            kinds = {classify(e[1]) for e in entries}
            result[name] = kinds.pop() if len(kinds) == 1 else UNKNOWN
        else:
            pending[name] = entries
    changed = True
    while changed and pending:
        changed = False
        for name in list(pending):
            entries = pending[name]
            if any(c in pending for e in entries for c, _ in e[2]):
                continue
            kinds = set()
            for _, flags, callees, _ in entries:
                flags = set(flags)
                for callee, checked in callees:
                    kind = result.get(callee, UNKNOWN)
                    if kind == ERR:
                        flags.add("e")
                    elif kind == NULL:
                        flags.add("V" if checked else "n")
                    else:
                        flags.add("O")
                kinds.add(classify(flags))
            result[name] = kinds.pop() if len(kinds) == 1 else UNKNOWN
            del pending[name]
            changed = True
    # What is left calls itself in a circle.
    for name in pending:
        result[name] = UNKNOWN
    return result


def sleepers(defs):
    sleeps = set(SLEEPS)
    changed = True
    while changed:
        changed = False
        for name, entries in defs.items():
            if name in sleeps:
                continue
            # Every definition has to agree: a weak default and its override
            # can differ.
            if entries and all(any(c in sleeps for c in e[3]) for e in entries):
                sleeps.add(name)
                changed = True
    return sleeps


def explain(name, defs, conv, sleeps):
    for file, flags, callees, always in defs.get(name, []):
        print(f"{name} in {file}")
        if flags is not None:
            print("  returns:", "".join(sorted(flags)) or "(nothing local)",
                  " ".join(f"{'k' if k else 'c'}:{c}={conv.get(c, 'undefined')}"
                           for c, k in callees))
        hits = [c for c in always if c in sleeps]
        if hits:
            print("  always calls:", ", ".join(hits))
    print(f"  => {conv.get(name, 'no pointer result')}"
          f"{', sleeps' if name in sleeps else ''}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("facts", nargs="+")
    ap.add_argument("-o", "--output", default="-")
    ap.add_argument("--explain", action="append", default=[],
                    help="print how the answer for this function came about")
    args = ap.parse_args()

    defs = parse(args.facts)
    conv = conventions(defs)
    sleeps = sleepers(defs)
    for name in args.explain:
        explain(name, defs, conv, sleeps)

    out = sys.stdout if args.output == "-" else open(args.output, "w")
    out.write("# linux-kernel-contracts 1\n")
    for kind in (ERR, NULL):
        for name in sorted(n for n, k in conv.items() if k == kind):
            out.write(f"{kind}\t{name}\n")
    for name in sorted(sleeps - SLEEPS):
        out.write(f"sleeps\t{name}\n")
    if out is not sys.stdout:
        out.close()
    count = collections.Counter(conv.values())
    print(f"{len(defs)} functions: {count[ERR]} return error pointers, "
          f"{count[NULL]} return NULL on failure, "
          f"{len(sleeps - SLEEPS)} always sleep", file=sys.stderr)


if __name__ == "__main__":
    main()
