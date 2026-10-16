# Clang Kernel Lab prototype

This directory contains three deliberately separated experimental components
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
  --target ClangKernelLabMap ClangKernelLab llvm-riscv-irq-sites -- -j1
```

The in-tree build is opt-in with `-DCLANG_ENABLE_KERNEL_LAB=ON`.  Local
qualification builds use one job and record disk usage before and after.

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
```

On macOS the pass-plugin suffix is `.dylib`.  The site-map test checks object
and linked `.text` identity, linked sidecar identity/load-bias fields, valid
object relocations, linked/object mode separation, and rejection of a
deliberately wrong-width relocation.

The C-map test additionally proves disabled/enabled object and linked `.text`
identity, validates the PC-relative relocation pair across linker relaxation,
and proves that the tool rejects a requested site dropped by code generation.
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
