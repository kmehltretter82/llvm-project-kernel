/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
OUTPUT_ARCH(riscv)
ENTRY(entry_path)

SECTIONS
{
  . = 0x80000000;
  .text :
  {
    __entrycheck_noinstr_start = .;
    KEEP(*(.noinstr.text))
    __entrycheck_noinstr_end = .;
    KEEP(*(.text))
  }
}
