/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */

	.section .noinstr.text,"ax",@progbits
	.globl entry_path
	.type entry_path,@function
entry_path:
#ifdef ENTRYCHECK_BAD
	call __sanitizer_cov_trace_pc
#endif
#ifdef ENTRYCHECK_UNKNOWN
	jalr ra, a0, 0
#endif
	addi a0, a0, 1
	ret
	.size entry_path, .-entry_path

	.section .text,"ax",@progbits
	.globl __sanitizer_cov_trace_pc
	.globl entrycheck_callback_impl
	.type entrycheck_callback_impl,@function
__sanitizer_cov_trace_pc:
entrycheck_callback_impl:
	ret
	.size entrycheck_callback_impl, .-entrycheck_callback_impl

	.section .note.GNU-stack,"",@progbits
