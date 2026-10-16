OUTPUT_ARCH(riscv)

SECTIONS
{
  . = 0x80000000;
  .noinstr.text : { KEEP(*(.noinstr.text)) }
  .text : { *(.text .text.*) }
  .rodata : { *(.rodata .rodata.* .srodata .srodata.*) }
  .data : { *(.data .data.* .sdata .sdata.*) }
  .bss : { *(.bss .bss.* .sbss .sbss.*) *(COMMON) }

  /* Keep map data after every runtime-allocated fixture section. */
  .riscv.linux_irq_expected : {
    KEEP(*(.riscv.linux_irq_expected))
  }
  .riscv.linux_irq_c_sites : {
    KEEP(*(.riscv.linux_irq_c_sites))
  }
}
