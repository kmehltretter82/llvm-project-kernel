#include "linux_irq_sites.inc"

        .text
        .globl bad_relocation_probe
        .type bad_relocation_probe,@function
bad_relocation_probe:
        nop
.Lbad_site:
        ret
        .size bad_relocation_probe, .-bad_relocation_probe

/*
 * The address field has the right width in the record but deliberately uses
 * a 32-bit relocation.  A linker can still make the final bytes look
 * plausible for a low address; the object validator must reject it.
 */
        .pushsection .riscv.linux_irq_sites,"a",@progbits
        .p2align 3
        .byte KLAB_SITE_VERSION
        .byte KLAB_SITE_RECORD_SIZE
        .2byte KLAB_SITE_KIND_ARCH_VECTOR_ENTRY
        .4byte (KLAB_FLAG_AFTER_PREVIOUS_RETIRE | \
                KLAB_FLAG_BEFORE_INSN_AT_SITE | KLAB_FLAG_ASSEMBLY | \
                KLAB_FLAG_MANUAL_ID)
        .4byte .Lbad_site
        .4byte 0
        .8byte 0x8899aabbccddeeff
        .8byte 0x0011223344556677
        .popsection
