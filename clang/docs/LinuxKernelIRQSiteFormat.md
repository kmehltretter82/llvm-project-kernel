# Experimental Linux IRQ site-map format

Status: version-one prototype for the RISC-V Linux kernel laboratory.

This document specifies the text-inert boundary records shared by Clang,
assembly, linked-image tools, QEMU, and FPGA trace adapters.  It does not
specify callback instrumentation.  Enabling map mode must not add an
instruction, a guest callback, an MMIO access, or a compiler barrier.

## Boundary meaning

A site address has one normative interpretation:

1. the instruction immediately preceding the site has retired;
2. the instruction beginning at the site has not executed; and
3. an injected interrupt is requested through the selected interrupt
   controller before execution can continue at the site.

QEMU must split or exit the translated block at a scheduled site.  A normal
pre-instruction plugin callback alone is insufficient if another instruction
can execute before the controller input is asserted and arbitrated.  FPGA
comparators use the equivalent retirement boundary.  Map mode needs no custom
guest opcode or MMIO marker.

## Fixed record

The initial record is exactly 32 bytes.  Integer fields use the ELF target's
byte order.  Version one is initially qualified for RV64 little-endian ELF.

| Offset | Size | Field | Meaning |
| ---: | ---: | --- | --- |
| 0 | 1 | `version` | Format version, currently 1. |
| 1 | 1 | `record_size` | Size in bytes, currently 32. |
| 2 | 2 | `kind` | Versioned semantic site kind; zero is invalid. |
| 4 | 4 | `flags` | Boundary and source properties below. |
| 8 | 8 | `address` | Relocation to the zero-byte text label; resolved VA after linking. |
| 16 | 8 | `site_id_low` | Low half of the stable identifier. |
| 24 | 8 | `site_id_high` | High half of the stable identifier. |

The canonical textual site ID prints `site_id_high` followed by
`site_id_low` as exactly 32 lower-case hexadecimal digits.

Records reside in `.riscv.linux_irq_sites`.  A Linux linker script must retain
that input section while producing `vmlinux`.  A post-link tool may emit a
sidecar and strip the records from a boot image only after resolving and
hashing them.

### Late C carrier

The first text-inert C implementation uses LLVM `!pcsections` metadata after
IR optimization.  LLVM specifies that this metadata does not affect
optimizations or generated code outside the requested data section.  For the
RV64 medium/large code model, `.riscv.linux_irq_c_sites` contains a separate
32-byte carrier:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 8 | Signed PC-relative delta from this field to the site. |
| 8 | 1 | Version. |
| 9 | 1 | Record size. |
| 10 | 2 | Kind. |
| 12 | 4 | Flags. |
| 16 | 8 | Site ID low half. |
| 24 | 8 | Site ID high half. |

Relocatable objects encode the first field with an `R_RISCV_ADD64` and
`R_RISCV_SUB64` pair.  The linked-image tool resolves this carrier into the
same sidecar representation as an assembly record.  Map compilation requires
`-mcmodel=medany` so LLVM uses an eight-byte PC field; other code models are
rejected rather than changing the record size.

PC metadata can be lost when an IR instruction is deleted or a backend fails
to propagate it.  Therefore the pass also emits one 24-byte entry in
`.riscv.linux_irq_expected` for every requested C site: kind, reserved zero,
flags, and the 128-bit ID.  The object/link tool requires the emitted and
expected sets to be identical.  A warning is not treated as coverage.

The first qualification fixture demonstrates backend and revision differences
that must remain visible.  Stock LLVM 22 RISC-V SelectionDAG preserves only the
store anchor, while its experimental GlobalISel preserves all four.  The lab
LLVM 24 backend fixes default SelectionDAG by identifying the actual target
call node and mapping return metadata to the lowered return chain; its four
records are checked in relocatable and linked ELF, and their resolved PCs are
checked against final `jal`, `sw`, and `ret` instructions.  LLVM 24 GlobalISel
instead drops only the publication-store record.  The expected table turns
both incomplete lanes into hard validation failures even when the backend
emits no warning.
The initial direct-instruction policy selector names an optimizer-last LLVM IR
opcode and an optional one-based occurrence inside a function.  Even when a
record survives, a source- or IR-relative selector does not promise
machine-instruction adjacency after scheduling.  The linked record's resolved
PC is authoritative for triggering; richer predecessor/successor claims need
an independent final-machine-code checker.

### Source marker prototype

The lab RISC-V Clang provides the experimental statement builtin
`__builtin_riscv_linux_irq_site(kind, ordinal)`.  Both arguments are constant
unsigned integers; version one accepts assigned kinds 1 through 39 and local
ordinals 0 through 65535.  It lowers to
`llvm.riscv.linux.irq.site`, which has no memory effects and is not a compiler
barrier.  The builtin is usable only with the matching map plugin.

The plugin deliberately does not attach final PC metadata to unoptimized IR.
It lets LLVM's initial SimplifyCFG, SROA, and EarlyCSE canonicalization expose
the surviving instruction, records that instruction's exact opcode and mapped
source location, removes the intrinsic, and rematerializes the anchor at the
optimizer-last extension point.  A missing, eliminated, duplicated, or changed
anchor is a compilation error.  This keeps the marker out of the main
optimizer while avoiding the metadata loss observed when `!pcsections` was
attached before SROA.

The prototype currently requires line-table debug locations and a normalized
project-relative path supplied through Clang prefix mapping.  Absolute paths
are reduced to a basename rather than entering a stable ID, so production
campaigns must use `-ffile-prefix-map` to avoid basename collisions.  It is
qualified only for non-inlined ordinary and single-module ThinLTO fixtures.
Across `-O0`, `-O1`, `-O2`, `-O3`, `-Os`, and `-Oz`, the current fixture
retains one expected kind-39 record and byte-identical object `.text`; at
`-O2` its linked PC equals the independent optimizer-last store selector.  A
same-revision ThinLTO link preserves that site and its ID while matching the
baseline's non-map allocated and executable sections, symbols, relocations,
and unwind data.  A cross-TU import/inlining fixture is additionally qualified
when section garbage collection leaves exactly one physical copy; multiple
surviving copies remain fail-closed and unsupported.  These bounded tests do
not yet establish whole-kernel inertness.

## Flags

| Bit | Name | Requirement |
| ---: | --- | --- |
| 0 | `AFTER_PREVIOUS_RETIRE` | Mandatory in version one. |
| 1 | `BEFORE_INSN_AT_SITE` | Mandatory in version one. |
| 2 | `ASSEMBLY` | Exactly one of `ASSEMBLY` and `C` is required. |
| 3 | `C` | Exactly one of `ASSEMBLY` and `C` is required. |
| 4 | `NOINSTR` | Site belongs to an entry/no-instrumentation region. |
| 5 | `MANUAL_ID` | ID was explicitly assigned instead of derived. |

Unknown flags are rejected during version-one qualification.  A future
format revision can define additional semantics without overloading these
bits.

## Version-one kind namespace

`clang/Basic/LinuxKernelIRQSiteKinds.def` is the numeric source of truth.  It
assigns kinds 1 through 39 to a namespaced experiment; architectural vector,
hard IRQ, NMI, exception, and softirq transitions; IRQ-mask operations;
preempt-count operations; trace-recursion and task-provenance transitions;
RCU and EQS transitions; lock and RT-wait events; migration controls;
scheduling boundaries; and barrier/state-publication sites.  Readers reject
unassigned version-one values.

Kind 1 requires a namespace in the sidecar.  Kinds 2 and 3 are architectural
vector entry and return.  Function, allocator, driver, transport, and firmware
names belong in the sidecar and are not part of the binary ABI.

## Stable identity

Automatic IDs will be the first 128 bits of a cryptographic digest over:

- a project-relative path after the build's prefix mapping;
- language linkage and function identity;
- semantic kind;
- source line and column or an explicit assembly token; and
- an explicit local ordinal.

Absolute developer paths must not enter the digest.  Assembly and frequently
moved sites may carry a reviewed manual ID.  Duplicate IDs in one linked image
are fatal.

Version one requires one physical linked instruction for each automatic ID.
A bounded ThinLTO test permits a mapped function to be imported and inlined
when section garbage collection removes its out-of-line body; the surviving
record resolves inside the caller and keeps the logical source ID.  Retaining
both bodies is rejected as a duplicate ID.  Two live inline copies currently
share a single LLVM PC-sections metadata node, causing AsmPrinter to emit two
PC deltas followed by one auxiliary payload; the resulting partial record is
also rejected.  Map mode must not prevent inlining to hide either condition,
because that would change generated code.  Supporting multiple physical
instances requires a future post-LTO instance identity and metadata-uniquing
scheme.

## Sidecar and schedule identity

The linked-image sidecar supplies information deliberately omitted from the
fixed record:

- architecture, endianness, ELF build ID, and complete `vmlinux` SHA-256;
- linked address and the runtime load-bias rule;
- compiler, linker, source, configuration, and schema identities;
- source/function/inline-stack strings keyed by site ID;
- semantic names and expected predecessor/successor state; and
- whether the site came from C, assembly, `noinstr`, or an entry section.

Every schedule must state whether an Nth-hit predicate is per-vCPU or global;
per-vCPU is the recommended deterministic default.  QEMU must reject a build
ID, image hash, architecture, load bias, or trigger-phase mismatch rather than
silently running a nearby schedule.

## Text-inertness gate

For a matched build with map mode disabled and enabled:

- object and linked executable sections must be byte-identical;
- executable symbol values and layout must match;
- code-affecting relocations and unwind data must match; and
- after removing map/note sections, the boot-image difference must be fully
  explained.

The phase-zero test proves object and linked `.text` identity for two
hand-authored RV64 assembly sites.  The C fixture additionally compares a
normalized object and linked-ELF fingerprint: all non-map allocated sections,
both executable sections (`.text` and `.noinstr.text`), meaningful symbols,
code relocations, and unwind bytes/relocations.  It passes with RISC-V linker
relaxation enabled and disabled and with section garbage collection.  The same
linked fingerprint, stable-ID check, and section-GC check pass for a bounded
single-module ThinLTO fixture with same-revision LLVM 24 tools; the LLVM 22
policy path is an independent passing control.  The fixture linker script
places map sections after all wildcarded runtime sections, and the regression
rejects orphan placement that would move a non-map symbol.  A bounded
split-DWARF lane also has byte-identical verified `.dwo` files, stable site
IDs, and matching object/linked runtime fingerprints for the LLVM 24 policy
and source paths and the LLVM 22 policy control.  A single-copy cross-TU
import/inlining lane passes with section GC; retained and multiply inlined
copies are explicit negative gates as described above.  Full Linux LTO,
cross-TU multiple-instance mapping, kernel debug packaging, and boot-image
qualification remain required.  GNU binutils 2.47 independently passes the
same non-LTO linked fingerprint, stable-ID/address, relaxation enabled/disabled,
and section-GC checks for the LLVM 24 policy/source and LLVM 22 policy lanes;
GNU ThinLTO is not claimed without a compatible LLVM-bitcode linker plugin.

## Reference implementation

`clang/utils/kernel-lab/irq_site_format.py` is the bounded reference encoder
and decoder for resolved records.  `riscv/linux_irq_sites.inc` emits the
assembly form.  `ClangKernelLabMap` attaches late C PC-section records selected
by a bounded policy file or planned by the RISC-V source builtin.
`llvm-riscv-irq-sites` validates linked RV64 images and emits the initial
sidecar; its `--validate-relocatable` mode additionally requires either one
`R_RISCV_64` assembly relocation or the exact C-carrier `ADD64`/`SUB64` pair
to an in-range text boundary.  These remain experimental tools and do not
establish an installed Linux ABI.
