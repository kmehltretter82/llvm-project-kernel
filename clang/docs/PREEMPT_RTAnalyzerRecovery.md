# Experimental PREEMPT_RT analyzer recovery checkpoint

This branch recovers the formerly local `special-rt` Clang Static Analyzer
work from the 2026-10-12 checkpoint.  It is a source-preservation branch, not
an upstream-ready or qualified release.

## Recovered history

The hosted starting point is `origin/superh-backend` at
`fa7f966eace560996fda6d83c7fdf65983c61839`.  The archived workspace recorded
three subsequent local commits:

* `7c31dc99b274020e9c76d942ce518d5b8a783904`
  (`[SuperH] Unwind information for the epilogue`);
* `dffd35db355cc827b1f14f08299a282ba307a2bb`
  (`[SuperH] Atomic operations as gUSA sequences on Linux`); and
* `d4c4707af2f80d77cc9e3cc20682517f499ea6d1`
  (`[Sema] Facts about structure members that are stored to but freed
  nowhere`).

Those objects had not been pushed.  They were recovered from their original
`git format-patch` mail, which preserves the patches, author data, messages,
and dates but not the original committer identity.  The reconstructed commits
therefore have different object IDs while retaining the archived changes.

The analyzer changes on top are the exact V4 source snapshot.  Its archived
candidate diff has SHA-256
`dd049e500136fb3111a54aa45bb49868851a5992078fe15810024d6e15740d1d`.
The recovered file hashes are:

| File | SHA-256 |
| --- | --- |
| `clang/include/clang/StaticAnalyzer/Checkers/Checkers.td` | `75a444b5b19a2abaa45559b7673398610c5e6652e55c7173adfd97b259d17bd3` |
| `clang/lib/StaticAnalyzer/Checkers/LinuxKernelModeling.h` | `63ce1d90f880dcf7fb4f465c92979808b508b954627b46df3f3cec5dcb0e7e89` |
| `clang/lib/StaticAnalyzer/Checkers/LinuxKernelModelChecker.cpp` | `49e950f1e598bc871cd877fd84183fa98cc138e02a53105eb08bce1692fb1517` |
| `clang/lib/StaticAnalyzer/Checkers/LinuxAtomicSleepChecker.cpp` | `0e26e377df9f0dce442b7860b328c6c42cb0383e5ab0e394c60e6896ffac9da2` |
| `clang/lib/StaticAnalyzer/Checkers/LinuxLockBalanceChecker.cpp` | `6da7f254536a879310de9b71bf72fa727feebf9f42dfdcd3898ff5d39bbb8a3d` |

## Scope

The experimental model is opt-in through
`alpha.linux.AtomicSleep:RTContext=true`; its default is `false`.  It extends
the Linux kernel model with IRQ state, preemption, bottom-half, RCU and
migration contexts, typed PREEMPT_RT lock waits, lock-balance checks, and
explicit unknown-effect reporting.  `AtomicSleep` and `LockBalance` are meant
to be enabled together.

V4 also adds two empty-by-default string options:

* `alpha.linux.AtomicSleep:RTContextManifest` imports explicitly reviewed,
  source/configuration/target-pinned entry contexts and typed call effects;
* `alpha.linux.AtomicSleep:RTContextManifestOutput` writes the actual compiler
  input identities and function bindings without inferring effects.

Both manifest options require `RTContext=true`.  Actual generated
`CONFIG_PREEMPT_RT` headers select RT behavior; a fixture macro is not a
substitute for a resolved kernel configuration.

## Qualification boundary

V3 is the last broadly tested model.  Its corrected harness completed 1,416
comparison records, default and explicit-false behavior matched the comparison
compiler on 354 records, and independent API/real-header controls passed
134/134.  Six genuine x86-64/arm64 Kconfig profiles and selected real netpoll
translation units were scanned.  These are bounded static-analysis results,
not runtime or general safety proofs.

The source in this branch is V4 importer development.  The archived build was
a successful hybrid incremental relink, not a clean LLVM build.  One bounded
API-fixture smoke test exited successfully and emitted input identities, but
did not produce a positive RT-wait diagnostic.  Manifest import semantics,
default compatibility, clean-build integration, LLVM regression tests, and a
real kernel translation unit have not been qualified for V4.

Known follow-up items at the recovery point included:

* separate manifest-validation failures from post-call coverage gaps in the
  test runner;
* run the prepared 174-record importer matrix and 89 adversarial cases; and
* perform a clean build plus focused analyzer regression tests before making
  correctness claims.

The zero-path visibility, opaque-call invalidation, positive BH/NMI accounting,
and foreign-static isolation gaps are now covered below.  The original
cross-target matrix and independent adversarial suite remain separate,
unfinished qualification work.

## In-tree qualification progress

The RISC-V kernel-lab branch now builds this snapshot as part of a complete
LLVM 24 Clang build.  `clang/test/Analysis/linux-rt-context.c` is the first
V4-specific regression test.  It runs for `riscv64-unknown-linux-gnu` and
checks both the opt-in RT model and the unchanged default mode.

The fixture currently covers raw-spin, preemption-disabled, hard-IRQ, NMI,
and IRQ-disabled rejection of an rtmutex-backed spinlock wait.  It also covers
the RT-permitted RCU, bottom-half-disabled, migration-disabled, and nested
RT-lock cases; balanced context exits; IRQ save/restore and query refinement;
and preemption-counter decoding for preempt, hard-IRQ, NMI, and RT bottom-half
fields.  The default mode reports none of the RT-specific diagnostics.

The first bounded V4 importer regression is also now in-tree.  It captures the
compiler-generated identity for a RISC-V translation unit, constructs a fully
pinned API-fixture manifest from those exact bindings, and imports hard-IRQ,
task, RCU, and softirq entries together with RT-wait, ordinary-sleep, and
unknown effects.  It checks both the operation diagnostic and the mandatory
post-call incomplete-context diagnostic.  A separate no-function translation
unit proves that malformed input and use without `RTContext=true` are visible;
manifest initialization no longer depends on beginning path analysis.

Multi-translation-unit manifests are isolated by the full captured binding,
not by function spelling.  A structurally valid record from an unloaded,
hash-pinned source is validated and ignored for the current AST.  An unbound
record claiming to come from a source that is loaded in the current AST still
rejects the manifest.  The primitive model also recognizes the public
`raw_spin_lock()`/`raw_spin_unlock()` spellings used by API fixtures, in
addition to the `_raw_*` and `__raw_*` leaves emitted by kernel wrappers.

Imported top-frame facts are now explicitly tagged in program state.  A
non-inlined unmodeled external call or an unresolved function-pointer call
invalidates those facts once, marks the tracked contexts and IRQ state
unknown, and emits a coverage-gap diagnostic at the call.  This prevents a
later imported wait/sleep effect from reusing a stale clean entry assumption.
The same calls without a manifest entry retain the pre-existing behavior.

Manifest `context.bh` is defined as a logical `local_bh_disable()` nesting
depth, not a raw softirq-counter value.  On RT each depth is therefore imported
as two `SOFTIRQ_OFFSET` units.  A `softirq` entry contributes its independent
one-unit active-softirq component before any explicit BH-disable depth.  An
NMI entry likewise contributes both `NMI_OFFSET` and its paired
`HARDIRQ_OFFSET`; direct `nmi_enter()`/`nmi_exit()` modeling uses the same
pairing and will not consume an unrelated hard-IRQ nesting level.  Positive
manifest regressions balance BH-only, softirq-plus-BH, direct NMI-exit, and
bulk preemption-counter exit paths.

The separate RISC-V port of the frozen campaign has now passed all 87 records
(29 cases under non-RT and both RT/BH fixture profiles) on clean commit
`b5294bcb4282`.  All 24 identity mutations were rejected as validation
failures, independently of the 60 expected post-call coverage gaps.  The
BH/NMI correction at `d1b37192986d` was followed by a second 87/87 pass with
the same diagnostic counts and no resource failures.  The original 174
x86-64/Arm64 records and the archived 89 adversarial cases have not been rerun.
This remains bounded API-fixture qualification; real-kernel translation-unit
coverage remains open.

The frozen phase-3 inputs, RISC-V runner, initial full result JSON, and compact
receipts are preserved under `clang/utils/kernel-lab/rt-context-campaign-v1`.
Larger generated evidence, binaries, kernel objects, and historical test
outputs remain outside the LLVM repository on the HETZNER volume under
`hetzner/recent-20261013/linux-work/dmadebug/rt-clang-work-20261012/`.
