# Clang Kernel Lab prototype

This directory contains four deliberately separated experimental components
for the Linux IRQ/PREEMPT_RT laboratory:

- `ClangKernelLabMap` is the text-inert map plugin.  Its policy path selects
  optimized IR at pipeline exit.  Lab Clang additionally lowers
  `__builtin_riscv_linux_irq_site(kind, ordinal)` to a dedicated marker: the
  plugin records its anchor after early canonicalization, removes the marker,
  and emits LLVM PC-section records at pipeline exit.  Both paths emit an
  independently checked expectation table and require RV64 Linux ELF with
  `-mcmodel=medany`.
- `llvm-riscv-irq-sites` validates the text-inert 32-byte site records and
  emits a linked-image JSON sidecar.  Its `--validate-relocatable` mode checks
  that every object record has exactly one `R_RISCV_64` relocation to an
  in-range text boundary before the linker can hide a malformed annotation.
- `rv-entrycheck` is the first linked-image entry audit.  Its strict versioned
  policy names executable sections or symbol-bounded regions and forbidden
  callbacks.  Schema one resolves direct RV64 calls and rejects every unknown;
  schema two can additionally bind an indirect call to exact target symbols at
  one symbol-plus-offset callsite; schema three recursively scans every linked
  function reached by those direct and declared indirect edges; schema four
  also follows conditional and unconditional exits that leave a linked function
  range.  All emit a deterministic JSON verdict.
- `ClangKernelLab` is an LLVM pass plugin for explicit callbacks and
  deterministic perturbation.  Loading a specification through
  `CLANG_KERNEL_LAB_SPEC` changes generated code; it is not map mode.

The normative record and trigger semantics are in
`clang/docs/LinuxKernelIRQSiteFormat.md`.  The broader implementation plan is
in `clang/docs/LinuxKernelRISCVLab.md`.

## Small standalone build

An installed LLVM can build only these tools, avoiding a full-tree build:

```text
cmake -S clang/tools/clang-kernel-lab \
  -B ../build-kernel-lab \
  -G Ninja \
  -DLLVM_DIR=/path/to/lib/cmake/llvm
cmake --build ../build-kernel-lab \
  --target ClangKernelLabMap ClangKernelLab llvm-riscv-irq-sites \
           rv-entrycheck -- -j1
```

The in-tree build is opt-in with `-DCLANG_ENABLE_KERNEL_LAB=ON`.  Local
qualification builds use one job and record disk usage before and after.
The entry checker is built and fixture-qualified both in-tree with lab LLVM 24
and standalone with stock LLVM 22.1.8; small MC API differences are selected
at compile time without changing the policy or output schema.

## Minimal validation

```text
python3 clang/utils/kernel-lab/tests/test_irq_site_format.py
python3 clang/utils/kernel-lab/tests/test_riscv_site_map.py \
  --clang /path/to/clang \
  --ld-lld /path/to/ld.lld \
  --llvm-objcopy /path/to/llvm-objcopy \
  --site-tool ../build-kernel-lab/llvm-riscv-irq-sites
python3 clang/tools/clang-kernel-lab/tests/test_callback_plugin.py \
  --clang /path/to/clang \
  --plugin ../build-kernel-lab/ClangKernelLab.so
python3 clang/tools/clang-kernel-lab/tests/test_map_plugin.py \
  --clang /path/to/clang --ld-lld /path/to/ld.lld \
  --gnu-ld /path/to/riscv64-elf-ld \
  --llvm-objcopy /path/to/llvm-objcopy \
  --llvm-readobj /path/to/llvm-readobj \
  --plugin ../build-kernel-lab/ClangKernelLabMap.so \
  --site-tool ../build-kernel-lab/llvm-riscv-irq-sites \
  --selectiondag-expect complete --global-isel-expect loss \
  --source-builtin-expect complete
python3 clang/tools/clang-kernel-lab/tests/test_selectiondag_backend.py \
  --clang /path/to/plugin-compatible/clang \
  --llc ../build-riscv-llvm/bin/llc \
  --ld-lld /path/to/ld.lld \
  --llvm-objcopy /path/to/llvm-objcopy \
  --llvm-objdump /path/to/llvm-objdump \
  --plugin ../build-kernel-lab/ClangKernelLabMap.so \
  --site-tool ../build-kernel-lab/llvm-riscv-irq-sites
python3 clang/tools/clang-kernel-lab/tests/test_rv_entrycheck.py \
  --clang /path/to/clang --ld-lld /path/to/ld.lld \
  --checker ../build-kernel-lab/rv-entrycheck \
  --linux-image /path/to/the-matching-vmlinux
../build-kernel-lab/rv-entrycheck \
  --policy clang/tools/clang-kernel-lab/examples/riscv-linux-entrycheck-v1.json \
  /path/to/vmlinux
../build-kernel-lab/rv-entrycheck \
  --policy clang/tools/clang-kernel-lab/examples/riscv-linux-entrycheck-v2.json \
  /path/to/the-matching-vmlinux
../build-kernel-lab/rv-entrycheck \
  --policy clang/tools/clang-kernel-lab/examples/riscv-linux-entrycheck-v3.json \
  /path/to/the-matching-vmlinux
../build-kernel-lab/rv-entrycheck \
  --policy clang/tools/clang-kernel-lab/examples/riscv-linux-entrycheck-v4.json \
  /path/to/the-matching-vmlinux
```

The initial entry-check lane folds its input `.noinstr.text` into output
`.text`, then exercises matched good, forbidden-callback, and unknown-indirect
fixtures with relaxation enabled and disabled.  It resolves both relaxed
`jal` and unrelaxed `auipc`/`jalr`, including a forbidden untyped alias of a
typed function.  Separate controls cover whole-section selection, missing and
overlapping regions, malformed policies (including escaped duplicate JSON
members), an RV64 relocatable object, and a linked RV32 image.  Schema-three
controls add safe and forbidden two-hop paths, rejected and exactly approved
indirect calls in a reached callee, a zero-sized target, cycle deduplication,
and recursive scanning of a declared indirect target, all with relaxation on
and off.  The checker emits
three distinct exit statuses: zero for a clean verdict, one for a semantic
finding, and two for invalid input.

`examples/riscv-linux-entrycheck-v1.json` is a deliberately strict starter
policy for Linux's `noinstr`, `irqentry`, and `softirqentry` linker-symbol
ranges.  On the current tinyconfig image it audited 2,840 bytes, 1,053
instructions, and 106 calls.  It resolved 102 direct calls and failed closed
on four indirect calls: two IRQ-dispatch callbacks in `handle_riscv_irq()` and
`generic_handle_arch_irq()`, the clocksource callback in
`sched_clock_noinstr()`, and the exception-vector dispatch in
`handle_exception()`.  The result is intentionally `FAIL`, not a waiver or a
kernel qualification.  The version-one forbidden-symbol list is also an
exact-name starter set, not complete runtime-family matching.

Schema two has no general "allow indirect calls" setting.  Each rule names a
caller symbol with a non-empty linked range, an instruction offset inside that
range, and one or more exact linked code symbols.  A rule must match an actual
indirect call, duplicate and stale rules fail, missing targets fail, and a
target cannot hide a forbidden alias.  The fixtures exercise typed and
untyped assembly aliases, relaxation on/off, a valid target set, a forbidden
target, a missing target, and an out-of-range or unused callsite.  An optional
`expected_image` object binds SHA-256 and build ID; both mismatch directions
are negative controls.  Portable synthetic fixtures omit the binding, while
the real-Linux policy requires it.

`examples/riscv-linux-entrycheck-v2.json` supplies reviewed target assertions
for the four schema-one findings in the current image.  The two IRQ sites use
the pair selected by the only linked `set_handle_irq()` caller,
`riscv_intc_irq` and `riscv_intc_aia_irq`; the clock site uses the three linked
sched-clock readers; and the assembly exception site lists the 15 unique
handlers represented by its vector table.  This bounded run resolves all 106
calls, consumes four exact callsite rules, and records 22 possible target
edges with no findings.  The policy is bound to image SHA-256
`6db55c4e53add1746038001c31cfebdfcf01f55d4af562741fbd1a2af08430ca`
and build ID `43105ae71ed6fb22b61788db6d5c2bd56d5b82c6`.

That schema-two `PASS` means only that the declared root regions satisfy the
declared exact target policy.  The target sets are reviewed assertions, not a
points-to proof, and callees are not recursively scanned yet.  It is therefore
not a kernel qualification and does not replace the schema-one fail-closed
discovery result.

Schema three turns every resolved direct target and every declared indirect
target into a new linked-function work item.  Functions are identified by an
exact executable address and one non-empty symbol size.  Cycles are scanned
once, while a 128-edge depth cap and 4,096-function cap fail closed.  Every
finding in the traversed graph includes the shortest discovered call path with
both node and intervening callsite addresses.  There is no terminal-symbol or
blanket external-call waiver.

`examples/riscv-linux-entrycheck-v3.json` deliberately carries the same four
reviewed root indirect rules into this wider discovery scope.  It reaches 560
functions and 43,315 instructions at depth 14, then correctly returns `FAIL`:
63 further indirect calls remain unknown and nine linked function ranges hit a
decode boundary.  Those counts are cross-checked with lab LLVM 24 and stock
LLVM 22.1.8.  The result is a reproducible backlog, not a safe-kernel claim.
Schema three's linear function scan does not model branch feasibility, tail
exits, exception edges, or state transitions.

Schema four treats every non-return branch whose linked target leaves the
current function range as a graph edge.  In-range conditional and unconditional
branches remain local CFG edges.  Direct exits require a function symbol at the
target; unresolved indirect exits fail unless a separate exact
`indirect_tail_targets` rule covers that instruction.  A call rule cannot
approve a tail site, overlapping call/tail rules are invalid, and every schema-
four path records whether each edge was a direct call, policy-approved indirect
call, conditional exit, direct tail, or policy-approved indirect tail.

The matched fixtures cover relaxed and unrelaxed direct tails, forbidden and
unknown tails, a local jump, a true conditional exit, an approved indirect
tail, and wrong-kind or overlapping policies.  The image-bound Linux schema-
four discovery has no indirect-tail rules: it reaches 1,026 functions and
76,904 instructions at depth 19, resolves 480 of 503 linked tail/control exits,
and returns `FAIL` for 23 indirect tail exits, 124 unknown calls, and ten decode
boundaries.  This expansion is evidence that state-aware graph delimiting is
required; it is not permission to add a broad terminal allowlist.

Symbol-bounded policy regions are necessary for a normal linked Linux image,
where input `.noinstr.text` is folded into `.text` but
`__noinstr_text_start` and `__noinstr_text_end` survive.  CFG feasibility,
exception edges, state ordering, and compiler-generated helpers still require
later gates and must not be treated as qualified.

The bounded external-Linux gate drives a real RISC-V Kbuild compile of
`kernel/softirq.c`.  Its default policy mode brackets `handle_softirqs()` with
entry/exit map records and can continue through a complete tinyconfig
`vmlinux` link:

```text
. /path/to/linux-work/scripts/env.sh
python3 clang/tools/clang-kernel-lab/tests/test_linux_kbuild_map.py \
  --linux /case-sensitive/linux \
  --build /case-sensitive/build/kernel-lab-riscv-softirq \
  --clang /path/to/lab/clang --ld-lld /path/to/lab/ld.lld \
  --gnu-ld /path/to/riscv64-elf-ld \
  --llvm-readobj /path/to/llvm-readobj \
  --plugin /path/to/ClangKernelLabMap.so \
  --site-tool /path/to/llvm-riscv-irq-sites \
  --configure-tiny --full-vmlinux
```

Passing `--source-sites` instead qualifies Linux's opt-in
`linux_irq_site()` wrapper.  All three variants receive identical line-table
and prefix-map flags; only the mapped variant loads the plugin and defines
`__RISCV_LINUX_IRQ_SITE_MAP__`.  The RISC-V Kconfig probe records whether the
compiler recognizes the builtin, while an ordinary build compiles the wrapper
to an argument-agnostic no-op.  The first source-qualified marker is the
terminal softirq-exit boundary after `current_restore_flags()`; it resolves to
the same object and final-image PC as the independent policy exit rule.

The driver always uses one make job, checks free space before every build,
uses fixed Kbuild identity fields, and never invokes a clean target.  Kbuild
does not track either the policy environment or source-map activation, so the
driver removes only the exact `kernel/softirq.o` command/dependency outputs
before each variant.  The full-image gate additionally requires the Linux
linker script to retain the three map sections as non-allocated host metadata;
allocated orphan placement is a failure because it changes runtime layout.
The final-image comparison requires every runtime program header, `System.map`,
allocated section other than `.notes`, meaningful symbol, relocation, and
unwind record to match.  It normalizes only the GNU build-ID payload after
proving that every other note field and byte is identical: the build ID is
expected to hash deliberately retained host metadata.  The file offset of an
otherwise identical `.riscv.attributes` section may move in the unstripped ELF
as non-allocated symbol and string tables grow; all runtime headers remain
exact.

On macOS the pass-plugin suffix is `.dylib`.  The site-map test checks object
and linked `.text` identity, linked sidecar identity/load-bias fields, valid
object relocations, linked/object mode separation, and rejection of a
deliberately wrong-width relocation.

The C-map test additionally proves disabled/enabled object and linked `.text`
identity, validates the PC-relative relocation pair across linker relaxation,
and proves that the tool rejects a requested site dropped by code generation.
It also links canonical high-half RISC-V text against a zero-address `INFO`
carrier, guarding the address-width modular arithmetic needed by Linux
`vmlinux` metadata.
Its normalized ELF fingerprint now compares every non-map allocated section,
every executable section, function/object and non-local symbols, relocations
targeting executable sections, and raw unwind sections plus their relocations.
The fixture contains both `.text` and `.noinstr.text`, runs with linker
relaxation enabled and disabled, and repeats the linked checks under section
garbage collection.  It also links matching ThinLTO baseline, disabled-plugin,
policy-map, and source-map objects with a same-revision `ld.lld`, applies the
same whole-ELF fingerprint, verifies stable site IDs, and repeats the policy
and source checks with section garbage collection.  Its linker script captures
all fixture `.text.*`, `.rodata.*`, `.data.*`, and `.bss.*` inputs before the
map sections; this prevents an orphan runtime section from being displaced by
retained metadata and makes that ordering rule part of the regression.
The cross-translation-unit ThinLTO fixture imports and inlines a mapped
publisher into `lto_irq_entry`.  With section GC leaving exactly one physical
copy, policy and source maps both resolve to the caller's store, preserve their
non-LTO IDs, and match the baseline ELF fingerprint.  Two unqualified shapes
are fail-closed regressions: retaining the out-of-line body as well as its
inline copy produces a duplicate ID, while two live inline copies share one
LLVM PC-sections metadata node and produce a partial fixed-size carrier.  The
decoder must reject both.  Map mode does not add `noinline`, because doing so
would violate text inertness.
The split-DWARF lane compiles every variant through the same output path,
requires byte-identical `.dwo` files, verifies each file with
`llvm-dwarfdump`, reapplies the object/linked inertness fingerprint, and checks
stable policy and source IDs.  Using one output path is intentional: a DWO
records its output pathname, so comparing different paths would manufacture a
debug-only difference unrelated to map mode.
The optional `--gnu-ld` lane repeats the non-LTO linked-image qualification
with a GNU RISC-V linker.  It covers the disabled, policy, and (when available)
source-builtin variants, checks the complete inertness fingerprint, requires
the same site IDs and linked addresses as `ld.lld`, and exercises relaxation
enabled/disabled plus section garbage collection.  It does not claim GNU
ThinLTO support: the current lane deliberately supplies no LLVM-bitcode linker
plugin.  GNU binutils 2.47 passes this lane with both lab LLVM 24 and the
policy-only LLVM 22 control.
Its expectation switches make backend/revision behavior explicit.  Stock LLVM
22 uses the defaults: SelectionDAG loses three sites and GlobalISel preserves
four.  The lab LLVM 24 command shown above requires four SelectionDAG sites and
expects GlobalISel to lose only the publication-store site.  All four object
and linked outputs remain text-identical to their matching controls; incomplete
coverage is still fatal.

The lab-Clang lane also checks the source builtin at `-O0`, `-O1`, `-O2`,
`-O3`, `-Os`, and `-Oz`.  Each lane emits one coverage-checked kind-39 site,
keeps object `.text` identical to its unannotated control, and resolves to the
same final store as the optimizer-last policy selector.  Two copies below
different absolute roots produce the same ID when `-ffile-prefix-map` gives
them the same project-relative name.  The current source prototype requires
line-table debug locations, rejects a changed/eliminated anchor, is qualified
for non-inlined ordinary and single-module ThinLTO fixtures, and does not imply
a compiler or memory barrier.  Loading a Clang that provides the builtin
without the matching map plugin is deliberately unsupported rather than a
silent no-op.  This bounded ThinLTO result does not yet qualify cross-TU
functions that produce multiple live physical copies or a Linux kernel LTO
link.  The bounded split-DWARF result likewise does not yet qualify the
kernel's complete debug packaging flow.

The lab branch also patches LLVM 24 SelectionDAG.  Its target test verifies
that PC-section labels are immediately before the RISC-V call and return:

```text
build-riscv-llvm/bin/llc -O2 -code-model=medium \
  llvm/test/CodeGen/RISCV/pcsections-call-return.ll \
  | FileCheck llvm/test/CodeGen/RISCV/pcsections-call-return.ll
```

`test_selectiondag_backend.py` is the wider gate.  It feeds optimizer-last IR
from the map plugin to the patched `llc`, requires all four expected records in
object and linked modes, compares mapped and unmapped `.text`, and checks the
resolved final PCs against `jal`, `sw`, and `ret`.  It supports a split
frontend/backend compatibility lane, and it now also passes with the complete
same-revision LLVM 24 Clang, plugin, and backend.

The map records identify final machine PCs, not source-level adjacency.  For
example, an IR instruction selected as "after call" can move away from the
call during instruction scheduling.  Consumers schedule only the resolved PC
and use the policy description as provenance, not as an unchecked assertion
about neighboring instructions.

Map rules currently support direct calls (`match: "call"`), function entry or
exit (`match: "function"`), and optimizer-last LLVM IR instructions
(`match: "instruction"`).  An instruction rule names its containing function
in `symbol`, an LLVM IR opcode such as `store`, and optionally a one-based
`occurrence`; its only valid position is `before`.  This is deliberately an IR
selector, not yet a stable source-level statement annotation or a final
machine-opcode selector.  The expectation table makes deletion or unsupported
backend propagation fatal instead of silently accepting incomplete coverage.
