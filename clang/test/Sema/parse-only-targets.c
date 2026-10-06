// Architectures that the Linux kernel supports and LLVM has no backend for.
// The frontend parses and checks code for them.
//
// RUN: %clang_cc1 -triple alpha-unknown-linux-gnu -target-cpu ev67 -fsyntax-only -verify %s
// RUN: %clang_cc1 -triple hppa-unknown-linux-gnu -fsyntax-only -verify %s
// RUN: %clang_cc1 -triple hppa64-unknown-linux-gnu -fsyntax-only -verify %s
// RUN: %clang_cc1 -triple sh4-unknown-linux-gnu -fsyntax-only -verify %s
// RUN: %clang_cc1 -triple sh4eb-unknown-linux-gnu -fsyntax-only -verify %s
// RUN: %clang_cc1 -triple microblaze-unknown-linux-gnu -fsyntax-only -verify %s
// RUN: %clang_cc1 -triple microblazeel-unknown-linux-gnu -fsyntax-only -verify %s
// RUN: %clang_cc1 -triple nios2-unknown-linux-gnu -fsyntax-only -verify %s
// RUN: %clang_cc1 -triple or1k-unknown-linux-gnu -fsyntax-only -verify %s
// RUN: not %clang_cc1 -triple shave-unknown-linux-gnu -fsyntax-only %s 2>&1 | FileCheck --check-prefix=UNKNOWN %s
// RUN: not %clang_cc1 -triple vax-unknown-linux-gnu -fsyntax-only %s 2>&1 | FileCheck --check-prefix=UNKNOWN %s
// RUN: not %clang_cc1 -triple sh4-unknown-linux-gnu -emit-obj -o /dev/null %s 2>&1 | FileCheck --check-prefix=NOCODE %s

// UNKNOWN: error: unknown target triple
// NOCODE: error: unable to create target

// expected-no-diagnostics

struct pair {
  char c;
  long long ll;
};

#if !defined(__linux__)
#error "the Linux macros are missing"
#endif

#if defined(__alpha__)
_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8, "LP64");
_Static_assert(sizeof(struct pair) == 16, "natural alignment");
_Static_assert(__builtin_types_compatible_p(__SIZE_TYPE__, unsigned long), "");
#if !defined(__alpha_bwx__) || !defined(__alpha_cix__) || !defined(__LITTLE_ENDIAN__)
#error "ev67 has BWX and CIX"
#endif
#elif defined(__hppa__) && defined(__LP64__)
_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8, "LP64");
_Static_assert(__builtin_types_compatible_p(__SIZE_TYPE__, unsigned long), "");
#if !defined(__BIG_ENDIAN__)
#error "PA-RISC is big-endian"
#endif
#elif defined(__hppa__)
_Static_assert(sizeof(long) == 4 && sizeof(void *) == 4, "ILP32");
_Static_assert(sizeof(struct pair) == 16, "natural alignment");
_Static_assert(__builtin_types_compatible_p(__SIZE_TYPE__, unsigned int), "");
#if !defined(__BIG_ENDIAN__)
#error "PA-RISC is big-endian"
#endif
#elif defined(__sh__) || defined(__microblaze__) || defined(__nios2__) || \
    defined(__or1k__)
_Static_assert(sizeof(long) == 4 && sizeof(void *) == 4, "ILP32");
_Static_assert(sizeof(struct pair) == 12, "64-bit members are aligned to 4");
_Static_assert(__builtin_types_compatible_p(__SIZE_TYPE__, unsigned int), "");
#else
#error "no architecture macro"
#endif

#if defined(__microblaze__) && defined(__LITTLE_ENDIAN__) != defined(__MICROBLAZEEL__)
#error "__MICROBLAZEEL__ goes with little-endian"
#endif
#if defined(__or1k__) && (!defined(__OR1K__) || !defined(__BIG_ENDIAN__))
#error "OpenRISC is big-endian"
#endif

// Register names and machine constraints are taken as they are written.
register unsigned long current_stack_pointer asm("r15");

unsigned long constraints(unsigned long a) {
  register unsigned long r asm("$30");

  asm volatile("op %0, %1" : "=z"(r) : "rJ"(a) : "t", "$28", "memory");
  return r + current_stack_pointer;
}

int printf(const char *, ...);

void formats(__SIZE_TYPE__ n, __PTRDIFF_TYPE__ d) {
  printf("%zu %td\n", n, d);
}
