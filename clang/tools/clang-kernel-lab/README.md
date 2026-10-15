# Clang Kernel Lab prototype

This directory contains three deliberately separated experimental components
for the Linux IRQ/PREEMPT_RT laboratory:

- `ClangKernelLabMap` is the text-inert, optimizer-last map pass.  It emits
  LLVM PC-section records plus an independently checked expectation table and
  requires RV64 ELF with `-mcmodel=medany`.
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
  --plugin ../build-kernel-lab/ClangKernelLabMap.so \
  --site-tool ../build-kernel-lab/llvm-riscv-irq-sites \
  --selectiondag-expect complete --global-isel-expect loss
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
Its expectation switches make backend/revision behavior explicit.  Stock LLVM
22 uses the defaults: SelectionDAG loses three sites and GlobalISel preserves
four.  The lab LLVM 24 command shown above requires four SelectionDAG sites and
expects GlobalISel to lose only the publication-store site.  All four object
and linked outputs remain text-identical to their matching controls; incomplete
coverage is still fatal.

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
