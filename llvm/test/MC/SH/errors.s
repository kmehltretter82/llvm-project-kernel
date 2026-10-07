# RUN: not llvm-mc -triple=sh4-unknown-linux-gnu -filetype=obj -o /dev/null %s 2>&1 | FileCheck %s

# What the assembler refuses.  A place in the code has to be in the section
# of the instruction and within its reach: there is no relocation that
# could leave it to the linker.  What is wrong with a number is said when
# the instruction is read, what is wrong with a place when all places are
# known.

	.text
back:
	.long	0
	bt	far
# CHECK-DAG: [[#@LINE-1]]:{{[0-9]+}}: error: the target is 304 bytes away, out of the reach of the instruction (-256 to 254)
	bra	elsewhere
# CHECK-DAG: [[#@LINE-1]]:{{[0-9]+}}: error: the target is not in this section, or it is not defined
	bsr	nowhere
# CHECK-DAG: [[#@LINE-1]]:{{[0-9]+}}: error: the target is not in this section, or it is not defined
	mov.l	odd,r1
# CHECK-DAG: [[#@LINE-1]]:{{[0-9]+}}: error: the target is not at a multiple of four bytes
	mov.l	back,r1
# CHECK-DAG: [[#@LINE-1]]:{{[0-9]+}}: error: the target is -16 bytes away, out of the reach of the instruction (0 to 1020)
	mov	#300,r1
# CHECK-DAG: [[#@LINE-1]]:{{[0-9]+}}: error: the immediate 300 does not fit in 8 bits
	mov.l	@(64,r1),r2
# CHECK-DAG: [[#@LINE-1]]:{{[0-9]+}}: error: the displacement 64 is not between 0 and 60
	mov.l	@(6,r1),r2
# CHECK-DAG: [[#@LINE-1]]:{{[0-9]+}}: error: the displacement 6 is not a multiple of 4
	mov.l	@(sym,r1),r2
# CHECK-DAG: [[#@LINE-1]]:{{[0-9]+}}: error: the displacement has to be a number
	nop
	nop
odd:
	.space	286
far:
	nop

	.data
elsewhere:
	.long	0
