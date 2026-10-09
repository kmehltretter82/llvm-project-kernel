#!/usr/bin/env python3
"""Report structure members that receive fresh allocations but are never freed.

Reads the "mem" lines of the facts files that -flinux-kernel-emit-facts=
writes, one per translation unit and pointer member:

    mem <record>::<member> <file> <flags>

with 'S' when a function of the unit stores a fresh allocation into the
member, 'F' when one frees it and 'E' when one hands it on (copies it to
another place, passes it through a parameter that is not a pointer to const,
or returns it).  A member with 'S' somewhere and neither 'F' nor 'E' anywhere
is reported: nothing in the program releases what was stored there.
"""
import argparse
import collections
import sys


def parse(paths):
    flags = collections.defaultdict(set)
    stores = collections.defaultdict(set)
    seen = set()
    for path in paths:
        with open(path, errors="replace") as f:
            for line in f:
                if line in seen:
                    continue
                seen.add(line)
                parts = line.rstrip("\n").split("\t")
                if len(parts) != 4 or parts[0] != "mem":
                    continue
                _, member, file, fl = parts
                flags[member] |= set(fl)
                if "S" in fl:
                    stores[member].add(file)
    return flags, stores


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("facts", nargs="+")
    ap.add_argument("--all", action="store_true",
                    help="list every member that is stored to, with its flags")
    args = ap.parse_args()
    flags, stores = parse(args.facts)
    leaks = sorted(m for m, f in flags.items()
                   if "S" in f and "F" not in f and "E" not in f)
    if args.all:
        for m in sorted(stores):
            print(f"{m}\t{''.join(sorted(flags[m]))}\t"
                  f"{', '.join(sorted(stores[m]))}")
    else:
        for m in leaks:
            print(f"{m}\tstored in {', '.join(sorted(stores[m]))}\t"
                  "never freed or handed on")
    print(f"{len(flags)} pointer members with facts, {len(stores)} stored to, "
          f"{len(leaks)} never freed or handed on", file=sys.stderr)


if __name__ == "__main__":
    main()
