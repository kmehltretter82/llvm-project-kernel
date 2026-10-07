// The macros that GCC predefines for SuperH, by processor.
//
// RUN: %clang_cc1 -E -dM -triple sh4-unknown-linux-gnu < /dev/null | FileCheck --match-full-lines --check-prefixes=COMMON,LE,SH4,FPU,DOUBLE,GUSA %s
// RUN: %clang_cc1 -E -dM -triple sh4-unknown-linux-gnu -target-cpu sh4-nofpu < /dev/null | FileCheck --match-full-lines --check-prefixes=COMMON,LE,SH4-NOFPU,GUSA %s
// RUN: %clang_cc1 -E -dM -triple sh4eb-unknown-linux-gnu < /dev/null | FileCheck --match-full-lines --check-prefixes=COMMON,BE,SH4,FPU,DOUBLE %s
// RUN: %clang_cc1 -E -dM -triple sh4-unknown-linux-gnu -target-cpu sh4-single-only < /dev/null | FileCheck --match-full-lines --check-prefixes=COMMON,SH4-SINGLE-ONLY,FPU %s
// RUN: %clang_cc1 -E -dM -triple sh4-unknown-linux-gnu -target-cpu sh4a < /dev/null | FileCheck --match-full-lines --check-prefixes=COMMON,SH4A,SH4,FPU,DOUBLE %s
// RUN: %clang_cc1 -E -dM -triple sh3-unknown-linux-gnu < /dev/null | FileCheck --match-full-lines --check-prefixes=COMMON,SH3,GUSA %s
// RUN: %clang_cc1 -E -dM -triple sh2-unknown-linux-gnu < /dev/null | FileCheck --match-full-lines --check-prefixes=COMMON,SH2,IMASK %s
// RUN: %clang_cc1 -E -dM -triple sh-unknown-linux-gnu < /dev/null | FileCheck --match-full-lines --check-prefixes=COMMON,SH2 %s
// RUN: %clang_cc1 -E -dM -triple sh2eb-unknown-linux-musl -target-cpu j2 < /dev/null | FileCheck --match-full-lines --check-prefixes=COMMON,BE,IMASK %s
//
// The sizes and types, which do not depend on the processor.
// COMMON-DAG: #define __BIGGEST_ALIGNMENT__ 4
// COMMON-DAG: #define __CHAR_BIT__ 8
// COMMON-DAG: #define __INT64_TYPE__ long long int
// COMMON-DAG: #define __INTPTR_TYPE__ int
// COMMON-DAG: #define __PTRDIFF_TYPE__ int
// COMMON-DAG: #define __SIZEOF_DOUBLE__ 8
// COMMON-DAG: #define __SIZEOF_LONG_DOUBLE__ 8
// COMMON-DAG: #define __SIZEOF_LONG_LONG__ 8
// COMMON-DAG: #define __SIZEOF_LONG__ 4
// COMMON-DAG: #define __SIZEOF_POINTER__ 4
// COMMON-DAG: #define __SIZEOF_WCHAR_T__ 4
// COMMON-DAG: #define __SIZE_TYPE__ unsigned int
// COMMON-DAG: #define __WCHAR_TYPE__ long int
// COMMON-DAG: #define __WINT_TYPE__ unsigned int
// COMMON-DAG: #define __GCC_HAVE_SYNC_COMPARE_AND_SWAP_4 1
// COMMON-DAG: #define __linux__ 1
// COMMON-DAG: #define __sh__ 1
//
// LE-DAG: #define __LITTLE_ENDIAN__ 1
// BE-DAG: #define __BIG_ENDIAN__ 1
//
// How GCC makes a sequence atomic by default: the kernel restarts it, or
// interrupts are masked.
// GUSA-DAG: #define __SH_ATOMIC_MODEL_SOFT_GUSA__ 1
// IMASK-DAG: #define __SH_ATOMIC_MODEL_SOFT_IMASK__ 1
//
// SH4-DAG: #define __SH4__ 1
// SH4A-DAG: #define __SH4A__ 1
// FPU-DAG: #define __SH_FPU_ANY__ 1
// DOUBLE-DAG: #define __SH_FPU_DOUBLE__ 1
//
// An SH-4 that does not use its unit says that it is an SH-3.
// SH4-NOFPU-DAG: #define __SH3__ 1
// SH4-NOFPU-DAG: #define __SH4_NOFPU__ 1
// SH4-NOFPU-DAG: #define __sh3__ 1
// SH4-NOFPU-NOT: #define __SH4__
// SH4-NOFPU-NOT: #define __SH_FPU
//
// SH4-SINGLE-ONLY-DAG: #define __SH4_SINGLE_ONLY__ 1
// SH4-SINGLE-ONLY-NOT: #define __SH_FPU_DOUBLE__
//
// SH3-DAG: #define __SH3__ 1
// SH3-DAG: #define __sh3__ 1
// SH2-DAG: #define __SH2__ 1
// SH2-DAG: #define __sh2__ 1
