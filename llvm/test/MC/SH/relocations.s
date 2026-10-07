# RUN: llvm-mc -triple=sh4-unknown-linux-gnu -filetype=obj -o %t.o %s
# RUN: llvm-readobj -r --symbols %t.o | FileCheck %s
# RUN: llvm-objdump -s -j .text -j .data %t.o | FileCheck %s --check-prefix=BYTES
# RUN: llvm-mc -triple=sh4eb-unknown-linux-gnu -filetype=obj -o %t.eb.o %s
# RUN: llvm-objdump -s -j .text %t.eb.o | FileCheck %s --check-prefix=BYTES-BE

# The relocations are for words of data.  They are written as GNU as writes
# them, which the linker of binutils depends on: the section is of type
# RELA, but the addend is in the word and the entry has none.  A local
# symbol is named by its section, with its offset in the word as well.

	.text
	.globl	f
f:
	nop
	nop
.L1:
	.long	ext+16
	.long	f+4
	.long	ext@GOT
	.long	ext@PLT-(.L2+2-.)
	.long	loc-(.L2+2)
	.long	_GLOBAL_OFFSET_TABLE_
	.long	ext@GOTOFF+8
	.long	tv@TPOFF+12
	.long	tv@GOTTPOFF
	.long	tv@TLSGD
	.long	tv@TLSLDM
	.long	tv@DTPOFF+4
	.long	ext-.
.L2:
	rts
	nop

	.data
loc:
	.long	f
	.long	loc+5
	.short	ext+3
	.byte	ext+1

# CHECK:      Section ({{[0-9]+}}) .rela.text {
# CHECK-NEXT:   0x4 R_SH_DIR32 ext 0x0
# CHECK-NEXT:   0x8 R_SH_DIR32 f 0x0
# CHECK-NEXT:   0xC R_SH_GOT32 ext 0x0
# CHECK-NEXT:   0x10 R_SH_PLT32 ext 0x0
# CHECK-NEXT:   0x14 R_SH_REL32 .data 0x0
# CHECK-NEXT:   0x18 R_SH_GOTPC _GLOBAL_OFFSET_TABLE_ 0x0
# CHECK-NEXT:   0x1C R_SH_GOTOFF ext 0x0
# CHECK-NEXT:   0x20 R_SH_TLS_LE_32 tv 0x0
# CHECK-NEXT:   0x24 R_SH_TLS_IE_32 tv 0x0
# CHECK-NEXT:   0x28 R_SH_TLS_GD_32 tv 0x0
# CHECK-NEXT:   0x2C R_SH_TLS_LD_32 tv 0x0
# CHECK-NEXT:   0x30 R_SH_TLS_LDO_32 tv 0x0
# CHECK-NEXT:   0x34 R_SH_REL32 ext 0x0
# CHECK-NEXT: }
# CHECK-NEXT: Section ({{[0-9]+}}) .rela.data {
# CHECK-NEXT:   0x0 R_SH_DIR32 f 0x0
# CHECK-NEXT:   0x4 R_SH_DIR32 .data 0x0
# CHECK-NEXT:   0x8 R_SH_DIR16 ext 0x3
# CHECK-NEXT:   0xA R_SH_DIR8 ext 0x0
# CHECK-NEXT: }

# A symbol of a thread is marked as one.
# CHECK:      Name: tv
# CHECK:      Type: TLS

# "ext+16", "f+4", nothing, the distance of the literal from two bytes
# behind .L2 (0x10 - 0x3a), the distance of loc from there (0x14 - 0x3a), ...
# BYTES:      Contents of section .text:
# BYTES-NEXT:  0000 09000900 10000000 04000000 00000000
# BYTES-NEXT:  0010 d6ffffff daffffff 00000000 08000000
# BYTES-NEXT:  0020 0c000000 00000000 00000000 00000000
# BYTES-NEXT:  0030 04000000 00000000 0b000900
# BYTES:      Contents of section .data:
# BYTES-NEXT:  0000 00000000 05000000 000001

# BYTES-BE:      Contents of section .text:
# BYTES-BE-NEXT:  0000 00090009 00000010 00000004 00000000
# BYTES-BE-NEXT:  0010 ffffffd6 ffffffda 00000000 00000008
