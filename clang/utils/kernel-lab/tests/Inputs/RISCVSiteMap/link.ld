OUTPUT_ARCH(riscv)
ENTRY(_start)

SECTIONS
{
  . = 0x80000000;
  .text : { *(.text) }
  .riscv.linux_irq_expected : {
    KEEP(*(.riscv.linux_irq_expected))
  }
  .riscv.linux_irq_c_sites : {
    KEEP(*(.riscv.linux_irq_c_sites))
  }
  .riscv.linux_irq_sites : { KEEP(*(.riscv.linux_irq_sites)) }
}
