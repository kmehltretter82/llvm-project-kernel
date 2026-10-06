#!/usr/bin/env python3
"""Turn the facts of a kernel build into a contracts file.

A build with -flinux-kernel-emit-facts=<file> appends one line for every
function that other translation units can call:

    fn <name> <file> <return sources> <functions it always calls>
    par <name> <file> <what it does with its pointer parameters>
    int <name> <file> <how its integer result can be negative>

This script closes those facts over the whole build and writes what the
second build reads with -flinux-kernel-contracts=<file>:

    err_ptr <name>    returns ERR_PTR() on failure and never NULL
    null    <name>    returns NULL on failure and never ERR_PTR()
    sleeps  <name>    sleeps whenever it runs to its end
    derefs  <name> <i>          dereferences parameter i whenever it is called
    nowrite <name> <i> <mask>   can return without writing through parameter i
    negative <name>   can return a negative number, which is an error code

The return sources are letters: E (ERR_PTR), e (the result of an error
pointer function), N (NULL), n (the untested result of a function that
returns NULL on failure), V (valid), M (read from memory), O (opaque).
",c:<name>" follows for a function of another translation unit whose result
is returned, ",k:<name>" if that result was tested for NULL first, and
",t:<name>" if it was only tested with IS_ERR().

A result that the caller tests counts as valid once the test has passed,
also where nothing is known about the function it comes from: the test is
what the author of the caller knows about it.

The parameter facts are "d<i>" (dereferences parameter i, counted from zero,
before its first branch), "p<i>:<name>:<j>" (hands it to parameter j of a
function of another translation unit there) and "w<i>:<mask>" (can return
without having written through it), or "-" for none.  The mask has the
classes of return values for which the parameter is left alone: 1 negative,
2 zero, 4 positive, 8 for a function that returns nothing.  Every definition
of a function with a pointer parameter has a line, so that a function with
several definitions, such as a weak default and its override, gets a
contract only as far as all of them agree.

The integer facts are "N" (a return statement has a negative constant, or
the function returns the result of a function in the same translation unit
that has one) or "-", and ",c:<name>" for a function of another translation
unit whose result is returned.  One definition that can return a negative
number is enough here: the caller has to be ready for it.

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
    """name -> list of (file, flags, [(callee, test)], calls) per definition.

    test is "c" (untested), "k" (tested for NULL) or "t" (tested with IS_ERR()).
    """
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
                    flags = set(first) if first[1:2] != ":" else set()
                    if first[1:2] == ":":
                        rest = [first] + rest
                    for token in rest:
                        callees.append((token[2:], token[0]))
                always = [] if calls == "-" else calls.split(",")
                defs[name].append((file, flags, callees, always))
    return defs


def parse_params(paths):
    """name -> {file: (derefs, passes, nowrite)}, one entry per definition.

    derefs is a set of indices, passes a list of (index, callee, index of the
    callee's parameter), nowrite a dict from index to mask.
    """
    defs = collections.defaultdict(dict)
    seen = set()
    for path in paths:
        with open(path, errors="replace") as f:
            for line in f:
                if line in seen:
                    continue
                seen.add(line)
                parts = line.rstrip("\n").split("\t")
                if len(parts) != 4 or parts[0] != "par":
                    continue
                _, name, file, facts = parts
                derefs, passes, nowrite = set(), [], {}
                try:
                    for token in facts.split(","):
                        if token.startswith("d"):
                            derefs.add(int(token[1:]))
                        elif token.startswith("p"):
                            index, callee, other = token[1:].split(":")
                            passes.append((int(index), callee, int(other)))
                        elif token.startswith("w"):
                            index, mask = token[1:].split(":")
                            nowrite[int(index)] = int(mask)
                except ValueError:
                    continue
                defs[name][file] = (derefs, passes, nowrite)
    return defs


def parse_ints(paths):
    """name -> list of (negative, [callee]) per definition."""
    defs = collections.defaultdict(list)
    seen = set()
    for path in paths:
        with open(path, errors="replace") as f:
            for line in f:
                if line in seen:
                    continue
                seen.add(line)
                parts = line.rstrip("\n").split("\t")
                if len(parts) != 4 or parts[0] != "int":
                    continue
                _, name, _, facts = parts
                first, *rest = facts.split(",")
                defs[name].append((first == "N",
                                   [t[2:] for t in rest if t.startswith("c:")]))
    return defs


def negatives(idefs):
    """The functions that can return a negative number."""
    result = {name for name, entries in idefs.items()
              if any(negative for negative, _ in entries)}
    changed = True
    while changed:
        changed = False
        for name, entries in idefs.items():
            if name in result:
                continue
            if any(c in result for _, callees in entries for c in callees):
                result.add(name)
                changed = True
    return result


def dereferences(pdefs):
    """The (name, index) pairs of parameters that are always dereferenced."""
    result = set()
    changed = True
    while changed:
        changed = False
        for name, entries in pdefs.items():
            candidates = set()
            for derefs, passes, _ in entries.values():
                candidates |= derefs | {i for i, _, _ in passes}
            for index in candidates:
                if (name, index) in result:
                    continue
                if all(index in derefs or
                       any(i == index and (callee, j) in result
                           for i, callee, j in passes)
                       for derefs, passes, _ in entries.values()):
                    result.add((name, index))
                    changed = True
    return result


def unwritten(pdefs):
    """(name, index) -> mask for the parameters that can be left unwritten."""
    result = {}
    for name, entries in pdefs.items():
        indices = set()
        for _, _, nowrite in entries.values():
            indices |= set(nowrite)
        for index in indices:
            mask = 15
            for _, _, nowrite in entries.values():
                mask &= nowrite.get(index, 0)
            if mask:
                result[(name, index)] = mask
    return result


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
                for callee, test in callees:
                    kind = result.get(callee, UNKNOWN)
                    if kind == ERR:
                        flags.add("e")
                    elif kind == NULL:
                        flags.add("V" if test == "k" else "n")
                    else:
                        flags.add("O" if test == "c" else "V")
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
                  " ".join(f"{t}:{c}={conv.get(c, 'undefined')}"
                           for c, t in callees))
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
    pdefs = parse_params(args.facts)
    derefs = dereferences(pdefs)
    nowrite = unwritten(pdefs)
    for name, index in sorted(derefs):
        out.write(f"derefs\t{name}\t{index}\n")
    for (name, index), mask in sorted(nowrite.items()):
        out.write(f"nowrite\t{name}\t{index}\t{mask}\n")
    idefs = parse_ints(args.facts)
    negative = negatives(idefs)
    for name in sorted(negative):
        out.write(f"negative\t{name}\n")
    if out is not sys.stdout:
        out.close()
    count = collections.Counter(conv.values())
    print(f"{len(defs)} functions: {count[ERR]} return error pointers, "
          f"{count[NULL]} return NULL on failure, "
          f"{len(sleeps - SLEEPS)} always sleep", file=sys.stderr)
    print(f"{len(pdefs)} functions with pointer parameters: "
          f"{len(derefs)} parameters are always dereferenced, "
          f"{len(nowrite)} can be left unwritten", file=sys.stderr)
    print(f"{len(idefs)} functions with integer facts: "
          f"{len(negative)} can return a negative number", file=sys.stderr)


if __name__ == "__main__":
    main()
