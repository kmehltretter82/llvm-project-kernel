        .section .text,"ax",@progbits
        .option norvc
        .globl _start
        .type _start,@function
_start:
        nop
        addi a0, a0, 1
        ret
        .size _start, .-_start
