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
inferring it from "after call."  Stock LLVM 22 SelectionDAG drops the entry,
call, and return records and remains the coverage-gate negative control.  The
lab branch adds a generic actual-call-node handoff plus RISC-V call and return
propagation; its LLVM 24 SelectionDAG preserves all four records.  LLVM 22
experimental GlobalISel provides an independent four-record control.  LLVM 24
GlobalISel instead drops the publication-store record without a diagnostic;
the expected-site table rejects the resulting three-record object and linked
image.  Every lane, including rejected lanes, keeps object and linked `.text`
identical.  An IR-relative selector still does not promise final instruction
adjacency; the resolved machine PC is the only scheduleable boundary.

Lab Clang now has the first source-facing interface,
`__builtin_riscv_linux_irq_site(kind, ordinal)`.  A dedicated intrinsic carries
the marker through only the initial canonicalization needed to expose its
surviving IR anchor.  The map plugin then removes it, records a strict pending
descriptor, and attaches `!pcsections` at optimizer exit.  The initial fixture
passes text-identity and coverage checks at all six Clang optimization modes,
uses prefix-mapped project-relative identity, and resolves to the same linked
store PC as the independent policy selector.  Line tables are currently
mandatory; changed anchors, missing coverage, and use outside RV64 Linux ELF
with the medium code model are hard errors.  Non-inlined ordinary and
single-module ThinLTO fixtures are the present qualification boundary;
cross-TU importing is qualified only when exactly one physical copy survives,
and a Linux LTO link remains outside it.

The first real-Linux wrapper, `linux_irq_site()`, is inert in normal builds and
expands to the builtin only when the Kbuild controller explicitly enables map
mode with the matching plugin.  A compiler feature probe makes mismatched
activation fail closed.  The marker at the terminal `handle_softirqs()` exit,
after task flags are restored, survives a tinyconfig RV64 Kbuild and resolves
to the same object and `vmlinux` PC as the independent optimizer-last policy
rule.  Baseline, disabled-plugin, and mapped objects retain the same executable
fingerprint; the final map sections remain non-allocated host metadata.
Stock Clang 22 leaves the feature probe unset, emits no map sections in a
normal build, and rejects forced activation at the wrapper's explicit guard.

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

`rv-entrycheck` consumes a linked RV64 ELF and a strict versioned policy.  Its
first bounded slice disassembles executable sections or symbol-bounded regions,
resolves direct calls across relaxed `jal` and unrelaxed `auipc`/`jalr`, rejects
named sanitizer callbacks, and fails closed on unresolved calls.  Symbol
ranges are required for a normal linked Linux image because `.noinstr.text` is
folded into `.text` while `__noinstr_text_start` and `__noinstr_text_end`
survive.  Matched linkable good/bad fixtures are the current gate; the checker
does not infer safety beyond the selected policy scope.

The first real-image run uses all three surviving Linux ranges: `noinstr`,
`irqentry`, and `softirqentry`.  On the source-wrapper tinyconfig `vmlinux`
(build ID `43105ae71ed6fb22b61788db6d5c2bd56d5b82c6`), the checker covered
2,840 bytes, 1,053 instructions, and 106 calls.  It resolved 102 direct calls
and returned `FAIL` for four unresolved indirect calls at
`0xffffffff800ea184`, `0xffffffff800ea1c8`, `0xffffffff800ea2ec`, and
`0xffffffff800ed6ac`.  These are respectively IRQ dispatch in
`handle_riscv_irq()` and `generic_handle_arch_irq()`, clocksource dispatch in
`sched_clock_noinstr()`, and exception-vector dispatch in
`handle_exception()`.  This is the intended fail-closed discovery result; no
target-set waiver or kernel qualification has been claimed.

Schema two adds a narrow, fail-closed way to state possible targets for those
four sites.  Every rule is anchored by a unique symbol, a non-empty linked
symbol range, and an instruction offset inside that range.  Every named target
must resolve to an executable code symbol; every rule must be consumed by an
actual indirect call; and forbidden aliases, missing targets, duplicate sites,
out-of-range offsets, and stale rules remain failures.  This also supports
assembly anchors such as the untyped `handle_exception` symbol without
treating arbitrary RISC-V mapping symbols as functions.

Schema two may bind a policy to an expected image SHA-256 and build ID.  The
Linux policy uses both and mismatch tests fail before a clean verdict can be
reported.  Synthetic cross-toolchain fixtures deliberately omit this optional
binding; their receipts say `identity_bound=false`.

For this exact image, the reviewed policy contains the two compiled RISC-V
root-IRQ handlers, the three possible sched-clock readers, and the 15 unique
exception-vector handlers.  The schema-two run resolves all 106 calls, uses
four exact callsite rules, and records 22 possible target edges with no
findings.  This is a root-region policy result only: the target sets are
asserted rather than inferred, and their callees are not recursively scanned.
It is not a kernel qualification.  The schema-one policy remains the negative
control that exposes all four sites as unknown.

Schema three recursively scans linked functions reached by both resolved
direct calls and every declared indirect target.  A reachable function must
have a defined executable symbol at the target address and one non-empty linked
size.  The traversal deduplicates cycles, fails closed at 128 call edges or
4,096 functions, and records the shortest discovered call path with each
finding, including every node and intervening callsite address.  Its matched
fixtures cover a safe two-hop chain, a forbidden callback and an unknown
indirect call in the callee, a zero-sized target, a cycle, and a declared
indirect target whose body must itself be scanned.  A matched control also
approves the exact indirect site inside the reached callee and recursively
checks its target.  Every case runs with linker relaxation enabled and
disabled.

The image-bound Linux schema-three policy deliberately reuses only the four
reviewed root indirect rules.  The transitive discovery reaches 560 functions,
119,746 bytes, 43,315 instructions, 1,605 calls, and depth 14.  It returns
`FAIL` with 63 further unknown indirect calls and nine decode failures.  Lab
LLVM 24 and stock LLVM 22.1.8 agree exactly on those counts.  This produces an
auditable backlog without a terminal-symbol waiver.  The graph is still a
conservative linear scan of each function range; it does not yet model branch
feasibility, tail calls, exception edges, or transition state, so neither its
paths nor the schema-two target assertions are a kernel qualification.

The complete checker will also consume the resolved site map, DWARF/BTF where
available, and expand from RISC-V vectors, irqentry, and noinstr regions to
conservatively reject or report unknown for:

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

As of 2026-10-16 on `kernel-lab-riscv`:

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
  markers under stock LLVM 22 SelectionDAG and is rejected by the
  emitted-versus-expected coverage gate;
- the lab LLVM 24 SelectionDAG passes the actual call node back to generic
  lowering and maps return metadata to the lowered return chain; its RISC-V
  regression places labels immediately before `call` and `ret`;
- the same patched SelectionDAG preserves all four expected records in a real
  relocatable and linked RV64 ELF; final PCs resolve to `jal`, `sw`, and `ret`,
  and object and linked `.text` match their unmapped controls byte for byte;
- stock LLVM 22 GlobalISel preserves all four expected records, while LLVM 24
  GlobalISel drops only kind 39, atomic-state-publish; the coverage gate rejects
  that three-record object and linked image, and both lanes retain byte-identical
  `.text` against their own controls;
- a RISC-V-only, assertions-enabled LLVM 24 `clang`, `llc`, both plugins, and
  the site tool build together using `-j1`; plugin configuration reads use a
  narrowly scoped LLVM I/O-sandbox bypass for the explicitly named JSON file;
- the complete LLVM 24 driver passes the patched SelectionDAG four-site lane;
  its RISC-V opt-in/disabled callback smoke test passes with four callbacks,
  one perturbation point, and zero disabled-mode hooks;
- the RISC-V source builtin accepts only assigned kind and bounded ordinal
  constants, lowers to a dedicated fail-closed intrinsic, and is consumed by
  a two-stage map pass; its kind-39 fixture has identical `.text`, a complete
  object/link sidecar, and the same linked store PC as the independent policy
  selector at `-O2`;
- the source fixture passes object text-identity and coverage at `-O0`, `-O1`,
  `-O2`, `-O3`, `-Os`, and `-Oz`; missing line tables are rejected, and two
  prefix-mapped checkout roots derive the same 128-bit ID;
- the C-map inertness gate covers two executable sections and compares all
  non-map allocated/executable bytes and layout, meaningful symbols, code
  relocations, and unwind sections/relocations in relocatable and linked ELF;
  linker relaxation on/off and section garbage collection all pass;
- same-revision LLVM 24 ThinLTO preserves both the policy and source-builtin
  sites, their stable IDs, and the complete linked-ELF inertness fingerprint;
  disabled-plugin and section-GC controls pass, while an LLVM 22 policy-only
  ThinLTO lane supplies an independent passing control;
- the ThinLTO fixture exposed and now guards a linker-integration requirement:
  all runtime `.text.*`, `.rodata.*`, `.data.*`, and `.bss.*` inputs must be
  placed before retained map sections so an orphan cannot move runtime state;
- a two-TU ThinLTO fixture imports and inlines the mapped publisher into its
  caller; with section GC leaving one physical copy, LLVM 24 policy/source and
  LLVM 22 policy lanes retain stable IDs, resolve to `lto_irq_entry`, and pass
  the full linked inertness fingerprint;
- cross-TU shapes with more than one physical copy fail closed: a retained
  out-of-line plus inline copy is duplicate-ID rejected, and two live inline
  clones are partial-record rejected because they share one PC-sections node;
  map mode deliberately does not change inlining to mask this limitation;
- the split-DWARF lane produces byte-identical verified `.dwo` files across
  baseline, disabled, policy, and source variants at one controlled output
  path, while object/link inertness and policy/source site IDs remain stable;
  the LLVM 22 policy control passes the same gate;
- GNU binutils 2.47 passes the non-LTO linked-image lane for lab LLVM 24 and
  the LLVM 22 policy control: disabled/policy/source inertness, site identity
  and linked address agreement with `ld.lld`, relaxation enabled/disabled,
  and section garbage collection all pass; this lane intentionally does not
  claim ThinLTO without an LLVM-bitcode linker plugin;
- a real RISC-V Linux tinyconfig Kbuild at Linux revision `0fcb05b72344`
  passes baseline, disabled-plugin, and mapped builds of `kernel/softirq.c`
  and a complete non-LTO `vmlinux` link, always with `-j1`; the disabled
  object is byte-identical, and both LLD and GNU binutils 2.47 preserve the
  two site IDs through a relocatable partial link;
- the Linux linker script retains the map carrier and expectation table as
  non-allocated `INFO` sections.  Mapped and unmapped final images have
  identical runtime program headers, `System.map`, executable/allocated data,
  meaningful symbols, code relocations, and unwind data.  Only the GNU build
  ID changes, as expected when it hashes the retained host metadata; the
  qualification separately proves that every other ELF note is identical.
  The receipt records config SHA-256
  `2331b13cc90f53802e2a795cacc4b67a96dd04f6e5037ce3bc0494b0811f97de`,
  baseline build ID `038bff326d6dbcbbcea3289e66aeb23959a3a8f7`, and mapped
  build ID `fd29523a119d9af4e976ecb0d038872c4c564540`;
- the linked Linux sites resolve to `handle_softirqs+0x22` at
  `0xffffffff8000c438` (softirq entry, ID
  `dcfbbfba966995b4cf1b8ca3357b0322`) and `handle_softirqs+0x17c` at
  `0xffffffff8000c592` (softirq exit, ID
  `117d16bff0e9c13476d765549becbba0`) in both `vmlinux.unstripped` and the
  final `vmlinux`;
- that Linux link exposed and now guards a decoder bug: a PC-section delta
  from a zero-VMA non-allocated carrier to canonical high-half kernel text
  must use 64-bit modular ELF arithmetic.  The corrected decoder still
  requires the result to land in executable text and a sized function, and a
  standalone high-half regression passes;
- the standalone LLVM 22 map plugin still builds and retains its original
  SelectionDAG-loss/GlobalISel-complete control results, with the source
  builtin explicitly unavailable in that lane;
- the recovered PREEMPT_RT analyzer has RISC-V primitive-context regressions,
  a compiler-identity-to-manifest round trip, and visible empty-TU validation;
- imported BH depths now use logical `local_bh_disable()` units, while NMI
  entries carry their paired hard-IRQ counter component; matched manifest and
  primitive exits are covered by focused RISC-V analyzer regressions;
- the frozen phase-3 manifest campaign is preserved in-tree, and its separate
  RISC-V port passes all 87 reviewed predicates on clean commit
  `b5294bcb4282`, with all 24 identity mutations rejected independently from
  60 explicit post-call coverage gaps; the BH/NMI correction at
  `d1b37192986d` retains the same 87/87 result and diagnostic counts;
- the source-derived QEMU/Linux inventory checker covers exactly 17 families,
  finds 16 existing CPU interrupt-entry hooks, and keeps Hexagon as the one
  explicit source gap; and
- no Linux boot, Linux LTO/debug-package/boot-image qualification, FPGA run,
  or correctness verdict has yet been claimed from this new branch.

The next compiler task is the Linux feature probe, no-op wrapper, and first
reviewed source annotation, followed by post-LTO identities for multiple
physical copies.  The next integration task joins the compiler-produced
sidecar to the independently qualified real PLIC schedule; exact-site TB
stop/resume and the controller lifecycle are already proven locally.
