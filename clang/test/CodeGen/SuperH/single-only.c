// RUN: %clang_cc1 -triple sh4-unknown-linux-gnu -target-cpu sh4-single-only -emit-llvm -o - %s | FileCheck %s --check-prefix=ONLY
// RUN: %clang_cc1 -triple sh4-unknown-linux-gnu -target-cpu sh4a-single-only -emit-llvm -o - %s | FileCheck %s --check-prefix=ONLY
// RUN: %clang_cc1 -triple sh4-unknown-linux-gnu -target-cpu sh4-single -emit-llvm -o - %s | FileCheck %s --check-prefix=WIDE
// RUN: %clang_cc1 -triple sh4-unknown-linux-gnu -target-cpu sh3e -emit-llvm -o - %s | FileCheck %s --check-prefix=SOFT

// With -m4-single-only double is float, as for GCC: the unit is used for
// nothing else.  long double keeps its 64 bits: the code generator computes
// it without the unit and passes it in general registers.  An SH-3E has
// such a unit as well and keeps a double of 64 bits.

_Static_assert(sizeof(long double) == 8, "long double is 64 bits everywhere");
#ifdef __SH4_SINGLE_ONLY__
_Static_assert(sizeof(double) == 4 && __DBL_MANT_DIG__ == 24, "double is float");
#else
_Static_assert(sizeof(double) == 8 && __DBL_MANT_DIG__ == 53, "double is double");
#endif

double twice(double x) { return x + x; }
long double wide(long double x) { return x + x; }

// ONLY-LABEL: define{{.*}} float @twice(float noundef %x)
// ONLY: fadd float
// ONLY-LABEL: define{{.*}} double @wide(double noundef %x)
// ONLY: fadd double

// WIDE-LABEL: define{{.*}} double @twice(double noundef %x)
// WIDE-LABEL: define{{.*}} double @wide(double noundef %x)

// SOFT-LABEL: define{{.*}} double @twice(double noundef %x)
// SOFT-LABEL: define{{.*}} double @wide(double noundef %x)
