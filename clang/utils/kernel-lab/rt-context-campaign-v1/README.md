# Frozen PREEMPT_RT manifest campaign

This directory preserves the phase-3 analyzer campaign recovered from
`/Volumes/HETZNER/hetzner/recent-20261013/linux-work/dmadebug/rt-clang-work-20261012/phase3-tests`.
It was copied byte-for-byte on 2026-10-16, and every entry listed in
`SHA256SUMS` was verified after the copy.

The files covered by `ORACLE-FREEZE.json` are an independent, pre-execution
semantic oracle: 29 API-fixture cases across six x86-64 and Arm64 profiles,
for 174 records.  Do not edit those frozen inputs or reinterpret them as a
kernel, Kconfig, runtime, or hardware qualification result.

`run.py` is the archived runner.  Its handoff documents two known limitations:
it combines manifest-validation failures with post-call context-coverage gaps,
and its foreign-static case conflicts with the importer's original
whole-manifest rejection policy.  It also targets x86-64 and Arm64, whereas
the kernel-lab compiler is intentionally built with only the RISC-V backend.
Keep fixes and the RISC-V adaptation separate from the frozen runner and
oracle.

Generated campaign runs are evidence artifacts and must use a fresh output
directory.  They are not source inputs and should not be committed here.
