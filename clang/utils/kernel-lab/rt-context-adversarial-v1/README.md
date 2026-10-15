# Frozen PREEMPT_RT importer adversarial review

This directory preserves the independent phase-3 importer review recovered
from
`/Volumes/HETZNER/hetzner/recent-20261013/linux-work/dmadebug/rt-clang-work-20261012/kernel-profiles/phase3-review`.
It was copied byte-for-byte on 2026-10-16.  Every file named in
`INDEPENDENT-SPEC-FREEZE.json` was rehashed successfully after the copy.

`ADVERSARIAL-TESTS.json` specifies 89 cases (75 P0 and 14 P1) that were frozen
before implementation review.  They cover schema and duplicate handling,
source/config identity, exact function binding, entry semantics, resolved and
unresolved callees, effect integration, legality, diagnostics, runtime input
drift, and qualification limits.  They are requirements, not recorded test
passes.  Do not modify the frozen oracle or source/API review snapshots.

New executable tests and qualification receipts should live outside the frozen
files and cite the exact adversarial case IDs they cover.  The in-tree RISC-V
regressions already address portions of `diagnostic-no-path`,
`unresolved-same-named-pointer`, and opaque-call preservation, but this does
not qualify the remaining matrix.
