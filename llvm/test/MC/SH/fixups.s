# RUN: llvm-mc -triple=sh4-unknown-linux-gnu -filetype=obj -o %t.o %s
# RUN: llvm-objdump -d --no-show-raw-insn %t.o | FileCheck %s
# RUN: llvm-objdump -s -j .text %t.o | FileCheck %s --check-prefix=BYTES
# RUN: llvm-readobj -S -r %t.o | FileCheck %s --check-prefix=NORELOC

# A place in the code is a distance in the instruction: words from four
# bytes behind a branch, long words from four bytes behind the address of a
# load rounded down to a multiple of four.  The assembler knows all of
# them, there are no relocations for them.  A global symbol of the section
# is reached like any other.

	.text
	.globl	entry
back:
	nop
entry:
	bt	fwd
	bf	back
	bt/s	fwd
	nop
	bf.s	entry
	nop
	bra	fwd
	nop
	bsr	entry
	nop
	mov.l	lit,r1
	mov.l	lit,r2
	mov.w	wlit,r3
	mova	lit2,r0
	mov.l	@(lit2,pc),r4
fwd:
	rts
	nop
	.align	2
lit:	.long	0x12345678
lit2:	.long	0
wlit:	.short	0x1234

# CHECK:       0: nop
# CHECK:       2: bt 0x20
# CHECK-NEXT:  4: bf 0x0
# CHECK-NEXT:  6: bt/s 0x20
# CHECK-NEXT:  8: nop
# CHECK-NEXT:  a: bf/s 0x2
# CHECK-NEXT:  c: nop
# CHECK-NEXT:  e: bra 0x20
# CHECK-NEXT: 10: nop
# CHECK-NEXT: 12: bsr 0x2
# CHECK-NEXT: 14: nop
# CHECK-NEXT: 16: mov.l 0x24,r1
# CHECK-NEXT: 18: mov.l 0x24,r2
# CHECK-NEXT: 1a: mov.w 0x2c,r3
# CHECK-NEXT: 1c: mova 0x28,r0
# CHECK-NEXT: 1e: mov.l 0x28,r4
# CHECK:      20: rts

# The fields: 13 words to fwd from 0x6, -4 to back from 0x8, ..., and for
# the loads 3 long words to lit from 0x18 (0x16 rounded down, and four), 2
# from 0x1c, 7 words to wlit from 0x1e, 2 long words to lit2 from 0x20.
# BYTES:      0000 09000d89 fc8b0b8d 0900fa8f 090007a0
# BYTES-NEXT: 0010 0900f6bf 090003d1 02d20793 02c702d4
# BYTES-NEXT: 0020 0b000900 78563412 00000000 3412

# A section with such a load is aligned to four bytes: the processor rounds
# the address of the instruction down.
# NORELOC:      Name: .text
# NORELOC:      AddressAlignment: 4
# NORELOC:      Relocations [
# NORELOC-NEXT: ]
