// RUN: %clang --target=xtensa -mabi=windowed -fsyntax-only -### %s 2>&1 \
// RUN:   | FileCheck --check-prefix=WINDOWED %s
// RUN: %clang --target=xtensa -mabi=call0 -fsyntax-only -### %s 2>&1 \
// RUN:   | FileCheck --check-prefix=CALL0 %s
// RUN: %clang --target=xtensa -fsyntax-only -### %s 2>&1 \
// RUN:   | FileCheck --check-prefix=NONE %s

// -mabi= names the calling convention for Xtensa, as it does for GCC.

// WINDOWED: "-target-abi" "windowed"
// CALL0: "-target-abi" "call0"
// NONE-NOT: "-target-abi"
