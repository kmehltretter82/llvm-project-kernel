OUTPUT_ARCH(riscv)

SECTIONS
{
  . = 0xffffffff80000000;
  .noinstr.text : { KEEP(*(.noinstr.text)) }
  .text : { *(.text .text.*) }
  .rodata : { *(.rodata .rodata.* .srodata .srodata.*) }
  .data : { *(.data .data.* .sdata .sdata.*) }
  .bss : { *(.bss .bss.* .sbss .sbss.*) *(COMMON) }

  /* Model Linux host-only metadata: non-allocated, with a zero VMA. */
  .riscv.linux_irq_expected 0 (INFO) : {
    KEEP(*(.riscv.linux_irq_expected))
  }
  .riscv.linux_irq_c_sites 0 (INFO) : {
    KEEP(*(.riscv.linux_irq_c_sites))
  }
}
