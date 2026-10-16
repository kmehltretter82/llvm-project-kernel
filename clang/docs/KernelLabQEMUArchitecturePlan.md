# Kernel Lab QEMU architecture plan

Status: source-audited implementation supplement, 2026-10-15

This document turns the Linux IRQ/RT observatory and RISC-V LLVM laboratory
plans into a QEMU work breakdown.  It fixes the architecture inventory,
defines the compiler/QEMU boundary precisely, separates the common recorder
and injector from architecture-native trace emulation, and assigns an
acceptance test to every Linux-capable QEMU target family in the inspected
trees.

The initial implementation is TCG-only.  It is a deterministic bug-finding
instrument, not a timing model and not evidence that an FPGA or production
SoC has identical latency.

## 1. Decisions

1. Build one common semantic event recorder and deterministic injector before
   building native trace encoders.
2. Start the vertical implementation on RV64 QEMU `virt`, PLIC, one vCPU,
   single-thread TCG, and icount.  Add AIA and SMP only after the PLIC lane is
   repeatable.
3. Keep three native-trace projects independent of the common facility:
   x86 Intel PT, Arm CoreSight ETM/ETE with TRBE, and RISC-V E-Trace with the
   Trace Control Interface and a RAM sink.
4. Load compiler site metadata from `vmlinux` and a sidecar.  Metadata-only
   mode has no guest callback, marker instruction, MMIO protocol, or custom
   guest ABI.
5. Inject through an interrupt-controller input.  Directly setting a CPU
   exception is a separately named unit-test operation and cannot qualify a
   controller adapter.
6. Keep the existing QEMU plugin discontinuity callback source-compatible.
   Add a versioned enriched event beside it.
7. Make disabled support compile away or reduce to a cheap empty-subscriber
   check.  It must not alter advertised guest features or machine layout.

## 2. Source evidence and exact scope

The inventory is derived from these local trees:

- QEMU `c1c18d1e640b64292859ce9f30f3c344edfb0294`;
- Linux `50d05c7c76c96b90462f24debacca971d2e86713`.

QEMU's `configs/targets/*-softmmu.mak` files were mapped to the directories in
Linux `arch/`.  Target spelling differences such as `hppa`/`parisc`,
`or1k`/`openrisc`, `ppc`/`powerpc`, and `sh4`/`sh` are explicit.  Arm and
Arm64 share a QEMU target implementation but are separate Linux architecture
and acceptance lanes.  This produces exactly 17 entries:

1. Alpha
2. Arm
3. Arm64
4. Hexagon
5. PA-RISC
6. x86
7. LoongArch
8. m68k
9. MicroBlaze
10. MIPS
11. OpenRISC
12. PowerPC
13. RISC-V
14. s390
15. SuperH
16. SPARC
17. Xtensa

AVR, RX, and TriCore have QEMU system targets but no matching Linux
architecture directory.  ARC, C-SKY, Nios II, and User-Mode Linux have Linux
architecture directories but no matching QEMU system target.  They are not
silently counted.

The executable inventory and its checker live in
`clang/utils/kernel-lab/qemu/`.  Run:

```text
check_architecture_matrix.py --qemu /path/to/qemu --linux /path/to/linux \
  --verify-revisions
```

Matrix schema version two also freezes the exact schedule vocabulary, checks
the replay-support names in `docs/system/replay.rst`, and carries source
evidence for open controller gaps.  The checker currently finds CPU-entry
interrupt callbacks for 16 of 17 entries.  Hexagon's
`hexagon_cpu_do_interrupt()` is the known missing hook.  PowerPC and SPARC are
reported as `AUDIT REQUIRED`, rather than being flattened into `PRESENT`.
This is source coverage, not semantic qualification.  The intentionally
failing `--require-qualified` mode is the future exit gate after all recorded
hook, replay, classification, and controller gaps have closed.

Two immediate semantic audit candidates are visible in the inspected source:

- PowerPC's callback classifier marks FIT, WDT, PIT, SMI, performance, and
  thermal events asynchronous, but currently sends external, decrementer,
  doorbell, and several other asynchronously delivered exceptions through
  the synchronous callback.
- SPARC32 and SPARC64 form external trap types by ORing a priority level into
  `TT_EXTINT`, while the final callback classification compares the complete
  value to bare `TT_EXTINT`.  Controller-driven levels therefore need a
  mask/range check.  This must be confirmed by the new tests before being
  reported as a QEMU defect.

QEMU's record/replay documentation names support for x86, Arm, Arm64,
RISC-V, MIPS, s390x, Alpha, PowerPC, m68k, MicroBlaze, OpenRISC, SPARC, and
Xtensa.  Hexagon, LoongArch, PA-RISC, and SuperH therefore need explicit
record/replay qualification or enablement; having an icount-capable TCG target
alone is not enough.  The matrix records these four as `QUALIFY`, and the
checker will force a re-audit if QEMU's documented platform list changes.

The inspected QEMU tree already has Intel PT CPUID constants, RTIT MSR state,
and migration state, but no TCG packet generator.  Arm TCG explicitly clears
TRBE, trace-filter, and trace-macrocell discovery fields.  No RISC-V E-Trace
encoder or Trace Control Interface device is present.

One scope correction is important: the inspected QEMU tree has a
`microblaze-softmmu` target but no `microblazeel-softmmu` target.  Big-endian
system emulation is the first MicroBlaze lane; a little-endian system lane is
a separate QEMU enablement task, not an existing acceptance configuration.

The current SiFive PLIC model has a more immediate semantic limitation.
`sifive_plic_irq_request()` sets pending state only for `level > 0`, ignores
deassertion, and retains no input-level or gateway state.  It therefore cannot
yet prove edge-versus-level lifecycle, or re-pend a held level after guest
claim and completion.  The matrix pins this source evidence as the open
`riscv-sifive-plic-level-lifecycle` gap so source drift cannot silently turn
the limitation into an assumed capability.

## 3. Compiler-to-QEMU contract

### 3.1 A site is a boundary, not a callback

The metadata-only compiler mode emits a zero-byte label and a retained record.
For scheduling, a site address has this normative meaning:

> Every earlier guest instruction has completed retirement; no instruction at
> the site's address has begun architectural execution.

Its only version-one wire spelling is
`AFTER_PREVIOUS_RETIRE/BEFORE_INSN_AT_SITE`.  A QEMU instruction callback
normally runs before an instruction but does not by itself stop the rest of
its translation block.  Therefore exact injection requires all of the
following:

1. load and validate the site map before vCPU execution;
2. force a translation-block boundary, or emit an internal TCG exit helper,
   at an armed site PC;
3. leave the vCPU before the site instruction executes;
4. perform the scheduled controller transition under the normal QEMU locking
   rules; and
5. resume normal arbitration and guest execution.

A plain plugin callback that queues work and permits the next instruction to
run does not meet the contract.

Site records on delay-slot architectures must say whether the label denotes a
branch, delay slot, or post-delay boundary.  The first implementation rejects
armed sites in delay slots.  Hexagon sites name packet boundaries, not an
individual operation inside a packet.

### 3.2 Required sidecar fields

The compact ELF record may use string-table indexes and relocations, while
the resolved sidecar contains:

- schema major/minor and record size;
- stable 128-bit site ID;
- semantic kind and flags;
- target architecture, endianness, and address width;
- link-time virtual address and containing symbol plus offset;
- source location and inline context when available;
- `noinstr`, entry, C, assembly, delay-slot, and packet-boundary flags;
- boundary phase;
- expected predecessor/successor state when specified;
- ELF build ID and SHA-256 of the exact `vmlinux`; and
- compiler/site-schema identity.

The run manifest supplies runtime load bias, the KASLR state, and the hash of
the sidecar.  Initial qualification uses `nokaslr`.  A hash or build-ID
mismatch is fatal; QEMU must never make a best-effort match by symbol name.

Hit counts use the exact values `per-vcpu` or `global`.  The initial RISC-V
scheduler supports only `per-vcpu`, matching the linked-image sidecar's
`default_hit_count_scope`.  A separate `per-hart` synonym is deliberately not
accepted: QEMU's schedule names vCPUs, while a sidecar or target payload may
also report architectural hart identity.  A global hit count in MTTCG requires
a specified atomic ordering and is not accepted in the deterministic lane.

### 3.3 No marker device in map mode

QEMU consumes the ELF/sidecar out of band.  FPGA tooling loads the same
resolved PCs into a comparator.  A NOP/HINT marker is allowed only in the
compiler's explicitly perturbing boundary mode.  An optional test IRQ device
may be added to generate edge and level interrupts, but that device is not the
site transport and is never instantiated by default.

## 4. Common event model

The semantic event model is an in-tree QEMU facility.  A plugin may consume
it, but target and controller code must not be reimplemented inside a plugin.

Each record has a fixed header:

- format version, header length, payload length, and event kind;
- run UUID, monotonic global sequence, vCPU sequence, vCPU/hart ID;
- deterministic instruction count and virtual clock;
- optional host timestamp marked non-comparable;
- architecture namespace and capability bits;
- architectural `from_pc` and `to_pc`;
- normalized class and architecture-native cause/vector;
- privilege/mode before and after entry;
- interrupt-mask/priority state before and after entry;
- stable controller endpoint ID and source number;
- nesting depth and paired-entry sequence; and
- loss/error flags plus a target-versioned payload.

Do not store QEMU pointers, enum values without a schema, or host byte order.
Use canonical little-endian encoding and explicit widths.

### 4.1 Event kinds and ordering

The first schema defines:

- `SITE_BOUNDARY`;
- `IRQ_LINE_ASSERT`, `IRQ_LINE_DEASSERT`, and `IRQ_PULSE`;
- `IRQ_PENDING`, `IRQ_SELECTED`, `IRQ_ACCEPTED`, `IRQ_ACK`, and `IRQ_EOI`;
- `TRAP_ENTER` and `TRAP_RETURN`;
- `VCPU_IDLE` and `VCPU_RESUME`;
- `DMA_BEGIN`, `DMA_VISIBLE`, and `DMA_COMPLETE` for opted-in devices;
- `INJECTION_ARM`, `INJECTION_FIRE`, `INJECTION_CANCEL`, and
  `INJECTION_REJECT`;
- `GUEST_STATE_SITE`, which is the host interpretation of site metadata, not
  a guest message; and
- `LOST_RECORDS` and `INVARIANT_FAILURE`.

The ordering for one external interrupt is source transition, controller
pending, target selection, CPU acceptance, architectural state commit,
handler entry, guest acknowledge where separate, EOI, architectural return,
and source deassertion.  A controller emits only stages it can prove and
advertises capability bits for the rest.

The existing public discontinuity callback remains an entry-only projection
of `TRAP_ENTER`.  It cannot manufacture cause, controller, acknowledgement,
return, or nesting information.

### 4.2 Stable interrupt endpoints

Generic `qemu_irq` objects do not always have a useful QOM owner or stable
path.  Register injection endpoints explicitly with:

- machine type and machine compatibility version;
- owning controller/device QOM path where available;
- GPIO bank/name and index;
- trigger type and polarity;
- edge/level protocol;
- legal operations; and
- a stable textual ID hashed into the binary stream.

An observer may record a line, but injection uses a wrapper/filter or a
controller-owned method.  Delaying only the deassertion of a level interrupt,
dropping one half of a pulse, or duplicating an MSI without controller state
updates is rejected unless that endpoint declares the operation legal.

### 4.3 Return events

Every CPU adapter adds a hook after architectural return validation and state
restoration.  Instruction-byte recognition in a generic plugin is
insufficient: several targets have multiple return forms, privileged checks,
delay slots, or firmware-mediated returns.  A return record pairs with QEMU's
entry sequence.  Underflow, wrong-vCPU pairing, or an impossible mode change
is an invariant failure.

## 5. Recorder, scheduler, and replay

### 5.1 Division of responsibility

The in-tree core owns semantic events, exact site stops, controller endpoint
registration, injection, QMP, and replay serialization.  A TCG plugin named
provisionally `libirqflight.so` owns the high-volume instruction/TB and
optional memory flight record.  Offline tools merge both streams by vCPU
sequence and icount.

This division avoids exposing private target structures through the plugin
ABI and keeps memory tracing optional.  A target may run the semantic core
without loading the flight recorder.

### 5.2 Schedule

A schedule is reviewable versioned JSON and has a canonical serialized hash.
A minimal rule resembles:

```json
{
  "version": 1,
  "vmlinux_sha256": "...",
  "site_map_sha256": "...",
  "machine": "virt",
  "cpu": "rv64",
  "icount": "shift=0,align=off,sleep=off",
  "trigger": {
    "site_id": "0123456789abcdef0123456789abcdef",
    "phase": "AFTER_PREVIOUS_RETIRE/BEFORE_INSN_AT_SITE",
    "scope": "per-vcpu",
    "vcpu": 0,
    "hit": 17
  },
  "action": {
    "endpoint": "riscv.virt.plic.source.10",
    "operation": "pulse",
    "width_icount": 1
  }
}
```

These strings are not presentation aliases: the checker locks them to the
same values emitted by `llvm-riscv-irq-sites`.  A schedule parser must reject,
not normalize, `before-site-instruction`, `vcpu`, an unknown phase, or a
sidecar whose image hash, site-section hash, load bias, build ID when present,
architecture, or site ID differs.  The schedule hashes the exact sidecar
bytes; `image.path` is diagnostic and never part of identity.

Reaching the boundary increments the selected vCPU's hit counter before an
action is evaluated.  A one-shot rule is consumed before its controller
operation, so resuming at the same PC cannot fire it twice.  If the site
instruction faults or is retried and execution later reaches that boundary
again, that is a new hit.  Accepted, rejected, and already-consumed actions
all receive semantic records.

Initial operations are assert, deassert, legal pulse, and delay by an exact
instruction count.  Later operations may hold a level, coalesce legal edges,
select a target CPU, delay a device completion, or expose DMA completion
before/after memory visibility.  Every accepted or rejected action is itself
recorded.  Direct CPU trap forcing uses the unmistakable operation name
`force-cpu-trap-test-only`.

### 5.3 Determinism

The reference command line uses one vCPU, `-accel tcg,thread=single`, and
icount with an explicit shift.  QEMU virtual time, not host wall time, drives
the schedule.  Inputs, firmware, disk overlays, network, machine version,
CPU model, topology, hashes, and random seed are recorded.  RISC-V `virt` is
unversioned in the inspected tree, so its reproducibility key is the exact
QEMU revision, machine type, CPU model, and complete non-default machine/QOM
properties; the manifest must not invent a `virt-X.Y` compatibility version.

Phase one writes a companion Kernel Lab event stream and replays the explicit
schedule.  Phase two adds a Kernel Lab asynchronous event to QEMU
record/replay, bumps the replay version, and qualifies the four currently
undocumented families.  The same run must produce a bit-identical normalized
stream after UUID and optional host timestamps are removed.

MTTCG is a separate stress lane.  It does not inherit a `100/100 deterministic`
claim from the single-thread lane.

## 6. RISC-V vertical slice

The first end-to-end implementation is deliberately narrow:

1. Parse and hash a hand-authored two-site RV64 map.
2. Make the translator terminate a TB at an armed site and exit before its
   instruction.
3. Extend `riscv_cpu_do_interrupt()` to publish cause, prior privilege,
   destination privilege, `xstatus` interrupt-enable state, `xepc`, and
   vector PC through the common event.
4. Register PLIC source inputs as stable endpoints and record claim/complete.
5. Provide a non-default synthetic edge/level IRQ source for qtest and the
   Linux lab driver; also retain timer and IPI tests that need no test device.
6. Record a bounded PC stream and selected stores around one early hardirq
   site.
7. Inject through the PLIC on the Nth site hit, detect the deliberately bad
   Linux ordering, and pass the corrected control 100/100 times.
8. Replay and compare the normalized stream.
9. Add RV32, SMP, then APLIC/IMSIC in that order.

Step 4 has a mandatory PLIC gateway sub-gate before the Linux 100-run claim:

1. assert a declared level source and observe pending, selection, acceptance,
   and claim;
2. complete it while the source remains asserted and require it to become
   pending and deliverable again;
3. deassert before completion and require no redelivery;
4. pulse a declared edge source and require exactly one delivery; and
5. repeat across reset plus save/restore, with source-level/gateway state in
   migration data.

The inspected `sifive_plic.c` cannot pass this test because its GPIO callback
ignores deassertion and has no source-level bitmap.  Either the PLIC gateway or
an explicit, architecturally honest source-gateway layer must acquire those
semantics before the endpoint advertises level operations.  The scheduler may
reject unsupported operations; it must not report a successful level test
after merely setting the pending bit directly.

Likely QEMU patch locations are a new `include/qemu/kernel-lab.h`,
`system/kernel-lab.c`, a QAPI schema, a small `hw/misc` test source,
`target/riscv/tcg/cpu_helper.c`, `hw/intc/sifive_plic.c`,
`hw/intc/riscv_aplic.c`, `hw/intc/riscv_imsic.c`, and dedicated qtests/TCG
tests.  Exact names should follow QEMU maintainer guidance.

The synthetic source is opt-in and test-only.  Production-device campaigns
later inject at virtio-net, virtio-block, UART, PCIe/MSI, or modeled DMA
completion points so that the device/controller interaction under study is
real.

## 7. Native trace flagships

These projects consume the same architectural transition ordering but do not
replace the common log.

### 7.1 RISC-V E-Trace first

Implement the ratified E-Trace v2.0 packet format and Trace Control Interface
v1.0 on `virt`:

1. one discoverable trace encoder per hart;
2. a minimal Trace RAM sink in SRAM mode, then system-memory mode;
3. baseline instruction trace with synchronization, direct-branch outcomes,
   indirect targets, privilege changes, traps, interrupts, and returns;
4. flush, wrap, stop-on-wrap, overflow, and multi-hart source identity;
5. optional funnel only after a one-hart encoder/sink is correct; and
6. Linux perf/AUX integration after a stable guest ABI exists.

Do not derive a claimed retired stream from translation alone.  QEMU plugin
instruction callbacks run before execution and an instruction can fault.
Tracing needs an execution point that is skipped on non-retirement plus the
common trap event for asynchronous discontinuities.

Acceptance has three oracles: specification packet vectors, a reference
decoder, and comparison of decoded control flow with the common recorder at
every trap boundary.  The same trace-control register map and packet corpus
become the golden model for CVA6 or another open FPGA core.

References:

- <https://docs.riscv.org/reference/e-trace/introduction.html>
- <https://docs.riscv.org/reference/trace-control-interface/tci_control_interface.html>

### 7.2 x86 Intel PT

Reuse QEMU's existing CPUID constants, RTIT state, and migration subsection,
but keep the TCG encoder behind a new CPU feature until functional:

1. validate CPUID leaf `0x14` and RTIT MSR read/write semantics;
2. implement single-range output first;
3. emit PSB/PSBEND, TNT, TIP/FUP, MODE, PIP, overflow, and synchronization
   packets sufficient for deterministic control-flow decode;
4. add ToPA traversal, watermark/stop/interrupt behavior, and migration;
5. add privilege, CR3, and address filters; and
6. add timing packets only when virtual-time semantics are documented.

Linux must discover the `intel_pt` PMU and `perf record -e intel_pt//` must
produce data accepted by both Linux perf and Intel `libipt`.  Branch-heavy,
page-fault, syscall, maskable IRQ, nested NMI, IRET, and later FRED fixtures
are compared with the common stream.  Host Intel PT passthrough is not the TCG
implementation and is not deterministic on non-Intel hosts.

Reference: <https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html>

### 7.3 Arm CoreSight ETM/ETE and TRBE

Arm32 and Arm64 share one flagship but retain separate acceptance lanes:

- Arm32 starts with an ETMv4-compatible source and a memory-backed CoreSight
  sink on `virt`.
- Arm64 starts with ETE/ETMv4 instruction-flow generation and a per-CPU TRBE
  sink, including its interrupt.

Implementation stages are feature discovery and register access, minimal
decodable instruction flow, context ID/VMID and exception-level changes,
address filters, TRBE base/limit/write-pointer/wrap/status behavior, discovery
and DT/ACPI wiring on `virt`, then migration.  Do not advertise fields that
remain RAZ/WI stubs.

Linux `perf cs_etm` plus OpenCSD must decode the stream.  Tests cover IRQ/FIQ,
SError/NMI-like entry as modeled, nested interrupts, ERET, context switch,
buffer wrap, overflow interrupt, and migration.  Arm Fast Models/FVP traces
are comparison material, not a cycle-accurate oracle.

Reference: <https://developer.arm.com/Tools%20and%20Software/Linux%20Kernel>

## 8. Architecture adapters and acceptance tests

Every row first passes a bare-metal or qtest transition test, then boots a
stock mainline Linux kernel with the feature disabled, then runs the common
Linux IRQ workload.  `Entry source` is the existing CPU transition code to
extend, not a claim that it already exposes all required fields.

| Linux lane | QEMU target and first machine | Entry source and controller | Concrete first acceptance |
| --- | --- | --- | --- |
| Alpha | `alpha`, `clipper` | `target/alpha/helper.c`; Typhoon | Pulse the Typhoon RTC/device input; pair assertion, `EXCP_CLK_INTERRUPT` or device vector, PAL entry, IPL state, and `HW_REI`; repeat on CPU1 for IPI routing. |
| Arm | `arm`, `virt,gic-version=2` | `target/arm/helper.c`; GICv2 | Inject a test SPI while CPSR.I is clear; verify IAR ID, IRQ mode/mask transition, EOI, and every supported AArch32 exception-return form. |
| Arm64 | `aarch64`, `virt,gic-version=3` | `target/arm/helper.c`; GICv3 | Exercise SPI, architectural timer PPI, and SGI; verify INTID, DAIF, source/destination EL, EOI/deactivate, nesting, and ERET. |
| Hexagon | `hexagon`, `virt` | `target/hexagon/hexswi.c`; L2VIC | First extend the existing `dtg_interrupt` functional fixture and add the missing discontinuity hook with event/cause and return pairing.  Establishing a maintained Linux boot is a phase-zero gate before claiming Linux parity. |
| PA-RISC | `hppa`, `B160L` | `target/hppa/int_helper.c`; LASI/Dino | Drive a LASI UART input; verify EIRR/EIEM selection, external interruption vector, IPSW masks, controller clear, and RFI. |
| x86 | `i386`/`x86_64`, `q35` | i386 TCG interrupt helpers; IOAPIC/APIC | Test legacy line, IOAPIC level IRQ, MSI, local APIC timer, and IPI; verify vector, IF/NMI state, remote-IRR/EOI, nesting, and IRET before adding PT. |
| LoongArch | `loongarch64`, `virt` | `target/loongarch/tcg/tcg_cpu.c`; PCH PIC/EXTIOI | Drive the UART PCH input through EXTIOI, then an IPI; verify ESTAT/ECFG selection, ERA, privilege/mask transition, controller clear, and ERTN. |
| m68k | `m68k`, `virt` | `target/m68k/op_helper.c`; Goldfish PIC | Trigger Goldfish RTC through the PIC; verify vector, old/new SR IPL, level behavior, nesting rejection/acceptance, and RTE. |
| MicroBlaze | `microblaze`, `petalogix-ml605` | `target/microblaze/helper.c`; Xilinx INTC | Trigger AXI timer through INTC; verify MSR IE/EIP, vector, ACK, and RTID.  Big-endian is the existing system lane; little-endian requires a new softmmu target. |
| MIPS | four endian/width targets, `malta` | `target/mips/tcg/system/tlb_helper.c`; CP0/i8259 or GIC | Exercise CP0 timer and an external Malta IRQ; verify Cause/Status/EPC, vector choice, pending clear, and ERET across 32/64-bit and BE/LE builds. |
| OpenRISC | `or1k`, `virt` | `target/or1k/interrupt.c`; CPU PIC | Distinguish tick from Goldfish external IRQ; verify PICMR/PICSR, EPCR/ESR, mask behavior, broadcast routing where enabled, and `l.rfe`. |
| PowerPC | `ppc`, `ppc64`, `ppce500` first | `target/ppc/excp_helper.c`; OpenPIC, later XIVE | External OpenPIC IRQ plus decrementer must both classify asynchronous, pair vector/MSR EE/EOI/RFI, and expose the current callback-classification gaps; later repeat on pseries/XIVE and doorbells. |
| RISC-V | `riscv64` then `riscv32`, `virt` | `target/riscv/tcg/cpu_helper.c`; PLIC then APLIC/IMSIC | Exact-site PLIC injection 100/100; verify cause, EPC, privilege, IE/PIE state, claim/complete, SRET/MRET, timer, and IPI; repeat with AIA and SMP. |
| s390 | `s390x`, `s390-ccw-virtio` | `target/s390x/tcg/excp_helper.c`; FLIC | Exercise CPU timer/external and virtio I/O interruption; record class/code, old/new PSW, pending dequeue, subclass mask, and PSW-based return. |
| SuperH | `sh4`/`sh4eb`, `r2d` | `target/sh4/helper.c`; sh-intc/R2D FPGA | Trigger TMU and FPGA IRL; verify INTEVT, SR.BL/IMASK, priority selection, deassert/ack, and RTE in both endian targets.  Keep J-Core AIC regressions separate. |
| SPARC | `sparc` `SS-5`, then `sparc64` `sun4u` | SPARC int32/int64 helpers; Slavio/PIL | Trigger Slavio timer at nonzero PIL; prove it is classified asynchronous, verify trap type/PIL/TPC/TSTATE and ACK, then RETT on v8 or DONE/RETRY on v9. |
| Xtensa | `xtensa`/`xtensaeb`, `virt` | `target/xtensa/exc_helper.c`; CPU PIC | Trigger timer and external IRQ; verify EXCCAUSE/EPC/PS.INTLEVEL, edge/level clear semantics, nesting by priority, and RFI for both endian targets. |

An adapter is complete only when timer, external IRQ, and an SMP IPI where
supported pair through return; exact-site injection repeats 100 times; a
deliberately invalid Linux ordering is detected; its corrected and
unmodified controls pass; and replay yields the same normalized stream.

## 9. Cross-architecture Linux workload

Use one small test module plus an early built-in fixture:

- controllable edge and level interrupts from the optional test source;
- local timer at low and high rates;
- reschedule, call-function, and TLB-shootdown IPIs;
- hardirq over task, idle, softirq, and another hardirq where legal;
- softirq raised from task and hardirq context;
- threaded IRQ under PREEMPT_RT;
- `local_irq_*`, preemption, RCU, trace-recursion, and provenance sites;
- tracing, lockdep, KCOV, KASAN, and KCSAN in separate lanes; and
- one test-only incorrect state transition with a matched fixed control.

The module reports semantic checkpoints through normal kernel logs or test
results.  QEMU does not rely on those messages for architectural entry
ordering.  Every run has a guest and host watchdog so a hang becomes a finite
artifact.

## 10. Patch decomposition

### Series A: specification and source audit

1. Event vocabulary, ordering, capability bits, and binary format.
2. Site-boundary and schedule specification shared with LLVM/Linux/FPGA.
3. Architecture matrix schema-two checker, replay-doc audit, and CI
   invocation.
4. Hand-authored binary/site/schedule fixtures.

### Series B: common QEMU core

1. Internal event bus and stable endpoint registry.
2. Versioned plugin projection without changing the old callback.
3. Binary writer, normalization tool, and overflow accounting.
4. QMP start/stop/query/rule commands and schedule parser.
5. Exact TCG site stop and icount scheduler.
6. Replay event, replay-version bump, and snapshot state.

### Series C: RISC-V vertical slice

1. Enriched RISC-V entry/return adapter.
2. PLIC lifecycle and injection endpoint.
3. Optional edge/level test source and qtests.
4. Linux boot/integration fixture and 100-run deterministic gate.
5. RV32, SMP, timer/IPI, APLIC, and IMSIC follow-ups.

### Series D: recorder

1. Per-vCPU bounded rings.
2. TB/instruction stream and site matching.
3. Opt-in address-only memory stream, then values.
4. BTF/symbol-selected stores.
5. Decoder, timeline view, and schedule minimizer.

### Series E: architecture fan-out

Land one family per reviewable series with its qtest, boot command, kernel
config, and known limitations.  Do x86 and Arm64 immediately after RISC-V to
challenge assumptions, then close Hexagon, PowerPC, and SPARC gaps before
mechanical fan-out.

### Series F-H: native trace

- F: RISC-V E-Trace plus Trace Control Interface/RAM sink.
- G: x86 TCG Intel PT; FRED is a separate companion.
- H: Arm ETM/ETE and TRBE.

Native packet libraries get packet-vector tests before CPU integration.

## 11. CI and resource discipline

All local builds and tests use one job:

```text
ninja -j1
meson compile -C build -j1
make -j1
```

Start with a target-restricted QEMU build such as `riscv64-softmmu`; do not
build all QEMU or LLVM targets merely to run a source inventory check.  Keep
build directories off the nearly full removable volume.  Before and after a
build, record `df -h` and `du -sh` for the build and artifact roots.  Preserve
configs, logs, command lines, diffs, hashes, and failing schedules before
removing only reproducible build output created by this project.

The architecture checker is source-only and needs no build.  Per-series gates
are ordered to fail cheaply: schema/unit tests, qtest, one minimal guest boot,
then the bounded stress or 100-run lane.

Normal source-audit CI uses `--verify-revisions` without strict qualification
and expects success with all gaps named.  A release-candidate job additionally
runs `--require-qualified`; it is expected to fail today on Hexagon's missing
hook, the PowerPC/SPARC classification audits, four replay lanes, and the
SiFive PLIC lifecycle gap.  Removing a recorded gap to make that job green is
not closure; its acceptance test and manifest status must change together.

## 12. Artifact and acceptance contract

Every run bundle contains:

- QEMU, Linux, LLVM, firmware, and optional RTL revisions plus dirty diffs;
- exact configure/build/run commands and single-job setting;
- machine version, CPU model, accelerator, topology, memory, and icount;
- kernel config, command line, and SHA-256 for `vmlinux`, image, DTB,
  initramfs, modules, and site map;
- schedule, endpoint inventory, seed, and capability set;
- raw semantic stream and flight record;
- normalized decoded timeline and invariant report;
- serial output, QEMU stderr, timeout/recovery result, and disk-space summary;
  and
- pass, fail, hang, unsupported, or infrastructure-error classification.

For a native trace flagship, the bundle also contains the raw packet stream,
decoder version/output, and a boundary-by-boundary comparison with the common
event stream.  Decoder acceptance alone is not proof of correct trace.

## 13. Reconciliation gap ledger

The two authoritative plans describe the intended system.  The following are
implementation gaps in the inspected trees, not completed capabilities:

| Gap | Current evidence | Closure gate |
| --- | --- | --- |
| Schedule/site-map parser | The local `irqsite` plugin now parses the schema-one linked-image sidecar and rejects the wrong phase, scope, target, record format, flags, duplicate ID, or missing selected site.  It does not parse a schedule or verify image/site-map hashes. | Parse a hand-authored schedule, reject every identity/phase/scope/hash mismatch, and round-trip its canonical hash. |
| Full sidecar provenance | The initial RV64 sidecar has image SHA-256, optional build ID, arch, endian, load bias, section hash, symbols, and sites.  It does not yet carry compiler/linker/config/source identity, inline stacks, kind-1 namespaces, or expected state. | Version the sidecar extension and make missing fields fatal only when that declared version requires them. |
| Exact site stop | The public-plugin prototype observes the pre-instruction callback and can terminate QEMU on an Nth per-vCPU hit.  Its result says `observational-stop-only` and `controller_action:false`; there is still no translator/TB-exit implementation. | Prove the vCPU exits after prior retirement and before the site instruction, including a same-PC resume negative test. |
| PLIC edge/level lifecycle | `sifive_plic_irq_request()` ignores low levels and stores no gateway input state. | Pass held-level redelivery, deassert-no-redelivery, one-pulse, reset, and migration qtests before advertising those endpoint operations. |
| Semantic entry/return stream | Existing plugin discontinuity callbacks are entry projections and Hexagon lacks one; target return pairing does not exist. | Add the versioned in-tree event, target return hooks, underflow tests, and old-callback compatibility tests. |
| Callback classification | PowerPC omits several asynchronously delivered classes; SPARC compares encoded external trap values to the bare base value. | Minimal target tests must fail before and pass after a separately reviewed classification change. |
| Record/replay breadth | QEMU documents 13 of the 17 families; Hexagon, LoongArch, PA-RISC, and SuperH are unnamed. | Record/replay a bounded timer/external-IRQ fixture twice and compare normalized output before marking each documented/qualified. |
| Linux boot breadth | In particular, Hexagon's maintained mainline boot path is not established by the source inventory. | Reproducible boot command, config, image hashes, timer event, and watchdog artifact for every lane. |
| Native trace flagships | There is PT state but no TCG encoder, Arm TCG masks trace features, and no RISC-V E-Trace/TCI model was found. | Packet-vector tests, reference decoder acceptance, and boundary comparison against the common stream; each remains independent of recorder completion. |

The initial QEMU implementation should consume only the fields the current
sidecar actually emits, while rejecting incompatible versions.  Missing
future provenance must remain visible as a capability limitation rather than
being guessed from host paths or symbol names.

### 13.1 Local observational checkpoint

The QEMU tree at `c1c18d1e640b64292859ce9f30f3c344edfb0294` has a local
prototype in `contrib/plugins/irqsite.c` plus an RV64 acceptance fixture in
`tests/tcg/riscv64/irqsite-observer.*` and
`tests/tcg/riscv64/test_irqsite_observer.py`.  The test feeds the plugin the
actual JSON emitted by `llvm-riscv-irq-sites`, reaches both zero-byte sites,
and stops on hit three for vCPU zero.  Negative cases require rejection of an
inject mode, a controller operation, the `before-site-instruction` phase
alias, and the `vcpu` scope alias.

This checkpoint proves sidecar loading, PC correlation, and per-vCPU hit
counting through the public plugin API.  It does not prove retirement, split a
translation block, assert a PLIC input, capture architectural trap state, or
implement replay.  QEMU's source policy also means this AI-assisted local
prototype is research evidence rather than an upstream submission.

## 14. Immediate execution order

1. Keep the schema-two 17-family checker green and convert the two
   classification candidates plus the PLIC lifecycle gap into minimal QEMU
   tests.
2. Keep the two-site observational acceptance checkpoint green while the
   core hook is developed; never relabel its callback as exact injection.
3. Implement the RV64 exact-site TB stop without IRQ injection, including
   consume-before-action and same-PC resume tests.
4. Add the enriched RISC-V event and PLIC endpoint lifecycle.
5. Add one opt-in edge/level source and deterministic QMP schedule.
6. Reproduce the deliberate hardirq ordering fixture 100/100 and archive the
   bundle.
7. Add return pairing, selected store recording, and normalized replay.
8. Challenge the common schema with x86 APIC/IRET and Arm64 GICv3/ERET.
9. Fan out the remaining adapters while RISC-V E-Trace begins independently.
10. Move minimized schedules to the FPGA comparator only after QEMU replay is
    stable.

The first useful result is not all-architecture coverage or a complete native
trace encoder.  It is one named RISC-V state boundary at which a real PLIC
interrupt can be requested, accepted, recorded outside Linux tracing, and
reproduced with identical architectural ordering.
