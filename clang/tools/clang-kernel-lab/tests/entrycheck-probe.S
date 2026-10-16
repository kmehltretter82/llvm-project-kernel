/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */

	.section .noinstr.text,"ax",@progbits
	.globl entry_path
	.globl entry_path_alias
	.type entry_path,@function
entry_path_alias:
entry_path:
#ifdef ENTRYCHECK_BAD
	call __sanitizer_cov_trace_pc
#endif
#ifdef ENTRYCHECK_UNKNOWN
	jalr ra, a0, 0
#endif
#if defined(ENTRYCHECK_TRANSITIVE_GOOD) || \
	defined(ENTRYCHECK_TRANSITIVE_BAD) || \
	defined(ENTRYCHECK_TRANSITIVE_UNKNOWN) || \
	defined(ENTRYCHECK_TRANSITIVE_ZERO_SIZE) || \
	defined(ENTRYCHECK_TRANSITIVE_CYCLE)
	call entrycheck_middle
#endif
#if defined(ENTRYCHECK_TAIL_GOOD) || \
	defined(ENTRYCHECK_TAIL_BAD) || \
	defined(ENTRYCHECK_TAIL_UNKNOWN) || \
	defined(ENTRYCHECK_TAIL_LOCAL) || \
	defined(ENTRYCHECK_TAIL_CONDITIONAL)
	call entrycheck_tail_source
#endif
	addi a0, a0, 1
	ret
	.size entry_path, .-entry_path
	.size entry_path_alias, .-entry_path_alias

	.section .text,"ax",@progbits
	.globl __sanitizer_cov_trace_pc
	.globl entrycheck_callback_impl
	.type entrycheck_callback_impl,@function
__sanitizer_cov_trace_pc:
entrycheck_callback_impl:
	ret
	.size entrycheck_callback_impl, .-entrycheck_callback_impl

	.globl entrycheck_safe_target
	.globl entrycheck_safe_alias
	.type entrycheck_safe_target,@function
.Lentrycheck_safe_local:
entrycheck_safe_alias:
entrycheck_safe_target:
	ret
	.size entrycheck_safe_target, .-entrycheck_safe_target

	.globl entrycheck_middle
	.type entrycheck_middle,@function
entrycheck_middle:
#ifdef ENTRYCHECK_TRANSITIVE_BAD
	call __sanitizer_cov_trace_pc
#elif defined(ENTRYCHECK_TRANSITIVE_UNKNOWN)
	jalr ra, a0, 0
#elif defined(ENTRYCHECK_TRANSITIVE_ZERO_SIZE)
	call entrycheck_zero_size
#elif defined(ENTRYCHECK_TRANSITIVE_CYCLE)
	call entrycheck_middle
#else
	call entrycheck_safe_target
#endif
	ret
	.size entrycheck_middle, .-entrycheck_middle

	.globl entrycheck_zero_size
	.type entrycheck_zero_size,@function
entrycheck_zero_size:
	ret

	.globl entrycheck_tail_source
	.type entrycheck_tail_source,@function
entrycheck_tail_source:
#ifdef ENTRYCHECK_TAIL_BAD
	tail __sanitizer_cov_trace_pc
#elif defined(ENTRYCHECK_TAIL_UNKNOWN)
	jr a0
#elif defined(ENTRYCHECK_TAIL_LOCAL)
	j .Lentrycheck_tail_local
.Lentrycheck_tail_local:
	ret
#elif defined(ENTRYCHECK_TAIL_CONDITIONAL)
	beqz a0, .Lentrycheck_safe_local
	ret
#else
	tail entrycheck_safe_target
#endif
	.size entrycheck_tail_source, .-entrycheck_tail_source

	.section .note.GNU-stack,"",@progbits
