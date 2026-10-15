/* SPDX-License-Identifier: GPL-2.0 */
/* Experimental RISC-V Linux IRQ laboratory site records. */

        .equ KLAB_SITE_VERSION, 1
        .equ KLAB_SITE_RECORD_SIZE, 32

        .equ KLAB_FLAG_AFTER_PREVIOUS_RETIRE, 1
        .equ KLAB_FLAG_BEFORE_INSN_AT_SITE, 2
        .equ KLAB_FLAG_ASSEMBLY, 4
        .equ KLAB_FLAG_NOINSTR, 16
        .equ KLAB_FLAG_MANUAL_ID, 32

#define KLAB_IRQ_SITE_KIND(name, value, text) \
        .equ KLAB_SITE_KIND_ ## name, value
#include "clang/Basic/LinuxKernelIRQSiteKinds.def"
#undef KLAB_IRQ_SITE_KIND

/*
 * Emit a zero-byte boundary at the current text address and one 32-byte
 * relocatable record in .riscv.linux_irq_sites.
 *
 * QEMU/RTL trigger contract:
 *   - the instruction preceding the label has retired;
 *   - the instruction at the label has not executed;
 *   - a scheduler must stop/split execution at the label before asserting an
 *     interrupt through the selected controller.
 */
        .macro KLAB_RISCV_IRQ_SITE kind, flags, id_lo, id_hi
.Lklab_irq_site_\@:
        .pushsection .riscv.linux_irq_sites,"a",@progbits
        .p2align 3
        .byte KLAB_SITE_VERSION
        .byte KLAB_SITE_RECORD_SIZE
        .2byte \kind
        .4byte ((\flags) | KLAB_FLAG_AFTER_PREVIOUS_RETIRE | \
                KLAB_FLAG_BEFORE_INSN_AT_SITE | KLAB_FLAG_ASSEMBLY | \
                KLAB_FLAG_MANUAL_ID)
        .8byte .Lklab_irq_site_\@
        .8byte \id_lo
        .8byte \id_hi
        .popsection
        .endm
