// RUN: %clang_cc1 -triple xtensa -E -dM %s | FileCheck --check-prefix=CALL0 %s
// RUN: %clang_cc1 -triple xtensa -target-abi call0 -E -dM %s \
// RUN:   | FileCheck --check-prefix=CALL0 %s
// RUN: %clang_cc1 -triple xtensa -target-abi windowed -E -dM %s \
// RUN:   | FileCheck --check-prefix=WINDOWED %s
// RUN: not %clang_cc1 -triple xtensa -target-abi other -E %s 2>&1 \
// RUN:   | FileCheck --check-prefix=UNKNOWN %s

// The Linux kernel needs to know the calling convention and stops with
// "Unsupported xtensa ABI" if neither macro is defined.

// CALL0: #define __XTENSA_CALL0_ABI__ 1
// CALL0-NOT: __XTENSA_WINDOWED_ABI__
// WINDOWED: #define __XTENSA_WINDOWED_ABI__ 1
// WINDOWED-NOT: __XTENSA_CALL0_ABI__
// UNKNOWN: error: unknown target ABI 'other'
