# RUN: not llvm-mc -triple=sh4-unknown-linux-gnu %s 2>&1 | FileCheck %s

# What the parser refuses.

	frob	r1,r2
# CHECK: [[#@LINE-1]]:2: error: no instruction of this name
	mov.b	@(4,r1),r2
# CHECK: [[#@LINE-1]]:{{[0-9]+}}: error: the instruction has no form with this operand
	add	r1
# CHECK: [[#@LINE-1]]:2: error: the instruction has more operands than this
	.big
# CHECK: [[#@LINE-1]]:2: error: the byte order is not the one of the target
