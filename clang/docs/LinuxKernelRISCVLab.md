# Linux-kernel-focused RISC-V Clang laboratory

Status: active implementation plan and execution ledger.

## Goal

Build a deliberately narrow LLVM/Clang research stack for finding and
reproducing Linux IRQ, hardirq/softirq, PREEMPT_RT, locking, allocator, tracing,
and driver failures.  RV64 is the first code-generation target, QEMU `virt` is
the first execution target, and an open application-class FPGA core is the
first RTL target.  CVA6 is the preferred initial FPGA correspondence target;
Rocket/BOOM adapters remain possible without changing the compiler contract.

This is not a new C language implementation.  It is a reviewable LLVM/Clang
patch stack plus object tools and small host-side adapters.  Generic pieces
must remain separable from Linux policy, RISC-V target code, experimental
perturbations, and the preserved PREEMPT_RT Static Analyzer prototype.

## Non-negotiable design rules

1. Map, boundary, and callback/perturb modes are different products.
2. Map mode emits zero-byte labels and metadata and must leave executable code
   byte-identical.
3. Callback and perturb modes visibly change code and can never substantiate
   an unperturbed timing claim.
4. Early assembly entry is first-class; a C-only pass is incomplete.
5. The host consumes ELF metadata.  Map mode creates no guest ABI.
6. QEMU injects through PLIC or AIA, not directly into a CPU exception path,
   except in a separately named unit-test mode.
7. Static-analysis silence and an absent runtime failure are never proofs of
   safety when coverage is incomplete.
8. Every finding needs stock Clang, lab-Clang-disabled, and GCC controls where
   the configuration is supported.
9. All local builds use one build job.  Free space is checked around builds,
   and disposable products are not retained.

## System architecture

### Layer A: text-inert site map

Clang, LLVM MC/AsmPrinter, and Linux assembly macros emit the shared 32-byte
record specified in `LinuxKernelIRQSiteFormat.md`.  An LLVM object tool resolves
relocations, validates IDs/kinds/sections, attaches source and build identity,
and writes the sidecar consumed by QEMU and FPGA tools.

The first annotations cover RISC-V vector entry/return, the first state
publication visible to tracing, IRQ-mask transitions, preempt-count changes,
softirq entry/exit, RCU transitions, and task-local provenance.

The first C path is a separate optimizer-last `ClangKernelLabMap` pass.  It
attaches LLVM `!pcsections` metadata to selected existing instructions under
an explicit RV64/ELF/medium-code-model gate.  A companion expected-site table
makes dropped metadata fatal in the object reader.  This is already useful for
surviving store/atomic publication instructions with the default SelectionDAG
backend.  Rules can select a direct call, function entry/exit, or a named
optimized-IR opcode and one-based occurrence inside a function.  The latter
lets a policy select the surviving publication `store` directly instead of
inferring it from "after call."  An explicitly experimental `-fglobal-isel`
lane preserves the four entry/call/publication/return anchors in the current
fixture without changing `.text`.  SelectionDAG still drops three of those
anchors and is retained as a required negative test.  Neither result turns an
IR-relative selector into a promise about final instruction adjacency; the
resolved machine PC is the only scheduleable boundary.

### Layer B: explicit callback and perturb mode

`ClangKernelLab` is an early pass-plugin prototype for code-changing
experiments.  A bounded JSON specification selects direct calls or function
entry/exit and requests callbacks, deterministic perturbation hooks, or both.
The plugin:

- rejects non-RISC-V targets and mismatched target OS policy;
- caps its input at 1 MiB and 4,096 rules;
- uses deterministic site keys;
- embeds callback-site metadata;
- rejects unsupported after-`invoke` and `musttail` sites in strict mode;
- is a no-op when no specification is provided; and
- marks a module to prevent accidental reinstrumentation during LTO.

This layer is suitable for allocator trylock forcing, bounded delay windows,
assertions, and runtime counters outside `noinstr`.  It is intentionally not
map mode.

### Layer C: linked-image checker

`rv-entrycheck` will consume `vmlinux`, the resolved site map, DWARF/BTF where
available, and a policy file.  Starting from RISC-V vectors, `.irqentry.text`,
and `.noinstr.text`, it will conservatively reject or report unknown for:

- fentry, KCOV, KASAN, KCSAN/TSAN, UBSAN, stack-protector, or other callbacks;
- compiler-generated libcalls, outlined atomics, thunks, and jump tables;
- unresolved indirect calls;
- tracing or calls reached before required state publication;
- unbalanced provenance, IRQ, preempt, RCU, migration, or recursion state;
- tail/exception-table exits that evade the visible graph; and
- a declared boundary invalidated by relaxation.

Negative linkable fixtures are required before the checker gates a kernel.

### Layer D: PREEMPT_RT static analysis

The preserved `alpha.linux.AtomicSleep:RTContext=true` and `LockBalance`
prototype remains opt-in.  It will consume the same versioned manifest rather
than grow an unrelated naming database.  Work proceeds in this order:

1. reproduce the V3 historical test boundary;
2. qualify the recovered V4 importer independently;
3. make manifest rejection and unknown effects visible;
4. add hardirq, NMI, softirq, RCU-EQS, and RT-lock controls; and
5. emit machine-readable candidate paths for deterministic QEMU schedules.

### Layer E: execution backends

QEMU loads the linked site sidecar, validates build identity, forces a TB
boundary at a selected site, and asserts a real PLIC input.  The first lane is
RV64 single-threaded TCG with icount; AIA/APLIC/IMSIC and SMP follow.  A bounded
host flight recorder supplies an independent architectural timeline even when
guest tracing is broken.

The FPGA interface consumes the same runtime PCs and exposes retirement PC,
instruction, hart, privilege, trap cause, selected CSR changes, stores, and a
monotonic retirement count.  Its comparator records interrupt request and
architectural acceptance separately.  Slow FPGA execution provides
visibility and ordering, not production timing equivalence.

## Bug-focused campaigns

### Softirq exit and tracing recursion

- Mark architectural IRQ entry/return and Linux hardirq/softirq state
  publication boundaries.
- Record when tracing recursion, task-local provenance, preempt count, RCU,
  and IRQ state become valid or invalid.
- Inject at every boundary between publication and its first consumer.
- Compare host architectural state with guest ftrace/lockdep state.
- Exercise the proposed extended softirq-exit sequence with a deliberate bad
  ordering and a corrected control, then minimize the schedule.

### Atomic allocator trylocks on RT

- Teach the analyzer about `GFP_ATOMIC`, reclaim context, raw versus sleeping
  locks, local locks, and RT lock waits without treating all allocator calls
  alike.
- Add map sites around allocator/reclaim/trylock state transitions.
- Use callback/perturb mode outside forbidden entry code to force selected
  trylock failures and deterministic delay windows.
- Test task, hardirq, softirq, threaded-IRQ, NMI-like, and panic paths with RT
  disabled and enabled.
- Separate legality, forward progress, latency, and memory-pressure verdicts.

### Wi-Fi RT 400/500+ failures

- Map hard IRQ, threaded IRQ, NAPI, softirq, workqueue, completion, firmware
  command, timeout/retry, DMA map/unmap, and reset boundaries.
- Preserve exact PCIe/USB/SDIO transport identity in every run; CPU emulation
  alone cannot reproduce a physical controller failure.
- Use QEMU only for driver state-machine and virtual-device schedules, FPGA
  for CPU/interrupt ordering, and real hardware for the final mechanism.
- Correlate firmware-command progress and timeout state with IRQ delivery,
  lock waits, workqueue execution, and DMA completion.

## Staged matrix

The initial matrix is RV64, QEMU `virt`, PLIC, one CPU, non-LTO, `-O2`, RVC
enabled, and relaxation enabled.  Dimensions are introduced independently:

- PREEMPT_NONE, PREEMPT_DYNAMIC, then PREEMPT_RT;
- one CPU, then 2/4/8 CPU SMP;
- PLIC, then AIA/APLIC/IMSIC;
- RVC on/off and relaxation on/`-mno-relax`;
- stock GCC, stock Clang, map mode, then explicit perturb mode;
- baseline, tracing, lockdep, KCOV, generic KASAN, and KCSAN lanes; and
- ThinLTO only after the non-LTO map and checker gates pass.

Pairwise combinations precede any larger diagnostic configuration.  RT is
combined with one facility at a time.

## Execution phases and exit gates

### Phase 0: preserve and specify

- Freeze `special-rt`; use the integration branch `kernel-lab-riscv`.
- Specify the fixed record, trigger phase, stable IDs, sidecar, and run
  manifest.
- Add parser round-trip and malformed-input tests.
- Emit assembly-only records in a trivial RV64 ELF and prove `.text` identity.

Exit: resolved records round-trip and two map sites do not alter object or
linked `.text`.

### Phase 1: LLVM object path and Linux annotations

- Implement the LLVM object reader/dumper and relocation validation.
- Add C/statement interface and final-code emission without optimization
  effects.
- Add Linux no-op wrappers, compiler feature test, assembly macros, and a
  retained linker section.
- Annotate a small RISC-V entry/provenance path.
- Expand inertness checks to symbols, executable sections, relaxations, and
  unwind information.

Exit: a non-LTO RV64 `vmlinux` sidecar is deterministic and map-on/off
executable sections match.

### Phase 2: deterministic QEMU vertical slice

- Load and verify the sidecar/build identity.
- Split the TB at one site and assert a PLIC interrupt at an explicit per-vCPU
  hit count.
- Record PC, `scause`, `sepc`, privilege, status/IE, controller lifecycle, and
  the first handler PCs.
- Reproduce a deliberate ordering bug and corrected control 100/100 times.

Exit: one command builds, boots, records, replays, and seals a result bundle.

### Phase 3: linked-image checking

- Implement direct-call graph and forbidden-callback checks.
- Add unresolved-indirect, state-ordering, tail-exit, and relaxation checks.
- Require all negative fixtures to fail and corrected fixtures to pass.

Exit: no unexplained edge or callback remains in the qualified early-entry
graph.

### Phase 4: analyzer and diagnostic lanes

- Requalify the PREEMPT_RT analyzer.
- Qualify tracing and lockdep, then KCOV, KASAN, and the RISC-V KCSAN lab fork.
- Pair each independently with RT and retain matched controls.

Exit: each lane has bounded positive/negative tests and documented limits.

### Phase 5: FPGA bridge

- Implement a CVA6 retirement adapter, comparator, injector, and bounded FIFO.
- Replay minimized QEMU schedules and normalize both traces to one vocabulary.

Exit: QEMU and one FPGA core agree on site identity and architectural ordering
for the selected corpus; request-to-accept latency is measured.

### Phase 6: physical hardware and upstream split

- Promote only bounded, recovery-safe experiments to BeagleV/other hardware.
- Separate generic LLVM, RISC-V, Linux, analyzer, QEMU, and test-only patches.
- Turn proven defects into minimal patches with accurate provenance.

## Artifact contract

Every published result records dirty diffs and revisions for LLVM, Linux,
QEMU, firmware, binutils, and RTL; compiler command/resource identity; config
and command line; hashes of images, DTB, initramfs, modules, and site map;
disassembly; map inertness result; schedule and seed; raw and normalized trace;
console output; timeout/recovery status; and an expected-versus-observed
summary.  Result directories are immutable after their final SHA-256 manifest.

## Current execution ledger

As of 2026-10-15 on `kernel-lab-riscv`:

- the recovered PREEMPT_RT branch is preserved and pushed separately;
- the version-one 32-byte resolved-record encoder/decoder exists;
- eleven format validation tests pass for little- and big-endian records,
  including shared-kind consistency, unknown-kind/flag, and duplicate-ID
  rejection;
- two assembly sites assemble and link in a real RV64 ELF;
- the two records resolve to the intended zero-byte boundaries;
- mapped and unmapped object and linked `.text` are byte-identical;
- `llvm-riscv-irq-sites` builds against installed LLVM 22, validates linked
  image/build/load-bias identity, emits a JSON sidecar, and maps sites back to
  sized function symbols;
- object mode validates one `R_RISCV_64` relocation per address field and
  rejects a wrong-width relocation that could otherwise link to plausible
  bytes;
- the optimizer-last C map pass emits one qualified 32-byte `!pcsections`
  carrier on a directly selected optimized-IR `store` without changing object
  or linked `.text`, and its object `ADD64`/`SUB64` relocation pair resolves
  correctly across linker relaxation;
- a four-site call/entry/return negative deliberately loses three backend
  markers and is rejected by the emitted-versus-expected coverage gate;
- compiling that same four-site fixture through RISC-V GlobalISel preserves
  all four expected records, and both its object and linked `.text` remain
  byte-identical to GlobalISel controls;
- the callback/perturb plugin builds against installed LLVM 22 using `-j1`;
- its RISC-V opt-in/disabled smoke test passes with four callbacks and one
  perturbation point;
- the source-derived QEMU/Linux inventory checker covers exactly 17 families,
  finds 16 existing CPU interrupt-entry hooks, and keeps Hexagon as the one
  explicit source gap; and
- no Linux boot, QEMU injection, FPGA run, or correctness verdict has yet been
  claimed from this new branch.

The next compiler task is to preserve PC-section metadata through the default
RISC-V backend (or emit the records at final Machine IR/AsmPrinter) so the lab
does not depend on experimental GlobalISel, and then add a stable source-level
statement interface.  Inertness checks must expand to all executable sections,
symbols, relaxation, and unwind data.  The next QEMU task is the RV64 exact-site
TB stop without injection, followed by the real PLIC endpoint and deterministic
schedule.
