#include "linux_irq_sites.inc"

        .section .text,"ax",@progbits
        .option norvc
        .globl _start
        .type _start,@function
_start:
        nop
        KLAB_RISCV_IRQ_SITE KLAB_SITE_KIND_ARCH_VECTOR_ENTRY, \
                KLAB_FLAG_NOINSTR, \
                0x8899aabbccddeeff, 0x0011223344556677
        addi a0, a0, 1
        KLAB_RISCV_IRQ_SITE KLAB_SITE_KIND_ARCH_VECTOR_RETURN, \
                KLAB_FLAG_NOINSTR, \
                0x7766554433221100, 0xffeeddccbbaa9988
        ret
        .size _start, .-_start
