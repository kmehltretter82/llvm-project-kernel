OUTPUT_ARCH(riscv)

SECTIONS
{
  . = 0x80000000;
  .text : { *(.text) }
  .bss : { *(.bss) *(COMMON) }
  .riscv.linux_irq_expected : {
    KEEP(*(.riscv.linux_irq_expected))
  }
  .riscv.linux_irq_c_sites : {
    KEEP(*(.riscv.linux_irq_c_sites))
  }
}
