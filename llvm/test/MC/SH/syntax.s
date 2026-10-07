# RUN: llvm-mc -triple=sh4-unknown-linux-gnu -show-encoding < %s | FileCheck %s
# RUN: llvm-mc -triple=sh4-unknown-linux-gnu -filetype=obj -o %t.o %s
# RUN: llvm-objdump -s -j .data %t.o | FileCheck %s --check-prefix=DATA

# The syntax of GNU as, where it is more than an instruction and its
# operands.

# Upper case, and blanks where they may be.
	MOV.L	@( 8 , R15 ) , R1
# CHECK: mov.l @(8,r15),r1 ! encoding: [0xf2,0x51]
	Cmp/Eq	# 5, r0
# CHECK: cmp/eq #5,r0 ! encoding: [0x05,0x88]

# A number is one of 32 bits, and an immediate of eight bits is any that
# fits with or without a sign.
	mov	#0xfffffff0,r1
# CHECK: mov #-16,r1 ! encoding: [0xf0,0xe1]
	mov	#0xff,r1
# CHECK: mov #255,r1 ! encoding: [0xff,0xe1]
	add	#(1 << 4) - 20,r2
# CHECK: add #-4,r2 ! encoding: [0xfc,0x72]

# Other spellings of a mnemonic.
	bf.s	1f
# CHECK: bf/s {{.*}} ! encoding: [A,0x8f]
	bt.s	1f
# CHECK: bt/s {{.*}} ! encoding: [A,0x8d]
	muls	r1,r2
# CHECK: muls.w r1,r2 ! encoding: [0x1f,0x22]
	fmov	@r1,fr2
# CHECK: fmov.s @r1,fr2 ! encoding: [0x18,0xf2]
1:

# The compare and swap of the J2, which the GNU as of most toolchains does
# not know.  The bytes are the ones of the assembler of the J-Core project.
	cas.l	r9,r6,@r0
# CHECK: cas.l r9,r6,@r0 ! encoding: [0x93,0x26]

# A comment begins with "!", and ";" ends a statement.
	nop ! nothing
# CHECK: nop ! encoding: [0x09,0x00]
	clrt ; sett
# CHECK: clrt ! encoding: [0x08,0x00]
# CHECK: sett ! encoding: [0x18,0x00]

# T is not a register that an instruction names, so "t" is a symbol.
	mov.l	t,r1
# CHECK: mov.l t,r1 ! encoding: [A,0xd1]
	.align	2
t:	.long	0

# Data: a word is two bytes, and the directives for data at any address.
	.data
	.byte	1
	.uaword	0x1122
	.ualong	0x33445566
	.uaquad	0x778899aabbccddee
	.word	0x1234
	.little
# DATA: 0000 01221166 554433ee ddccbbaa 99887734
# DATA: 0010 12
