// RUN: %clang_cc1 -triple sh4-unknown-linux-gnu -fsyntax-only -verify %s
// RUN: %clang_cc1 -triple sh4-unknown-linux-gnu -target-cpu sh4-nofpu -fsyntax-only -verify %s
// RUN: %clang_cc1 -triple sh4eb-unknown-linux-gnu -fsyntax-only -verify %s

// The data model of GCC: nothing is aligned to more than four bytes, also
// not for __alignof__.
struct pair {
  char c;
  long long ll;
};
struct with_double {
  char c;
  double d;
};
_Static_assert(sizeof(long) == 4 && sizeof(void *) == 4, "ILP32");
_Static_assert(sizeof(struct pair) == 12, "long long is aligned to 4");
_Static_assert(sizeof(struct with_double) == 12, "double is aligned to 4");
_Static_assert(__alignof__(long long) == 4, "");
_Static_assert(__alignof__(double) == 4, "");
_Static_assert(sizeof(long double) == 8, "long double is double");
_Static_assert(__builtin_types_compatible_p(__SIZE_TYPE__, unsigned int), "");
_Static_assert(__builtin_types_compatible_p(__WCHAR_TYPE__, long), "");
_Static_assert((char)-1 < 0, "char is signed");

struct dummy {
  int x __attribute__((aligned));
};
_Static_assert(__alignof__(struct dummy) == 4, "the largest alignment");

// va_list is a pointer without a floating point unit and five pointers
// with one.
#ifdef __SH_FPU_ANY__
_Static_assert(sizeof(__builtin_va_list) == 20, "");
#else
_Static_assert(sizeof(__builtin_va_list) == 4, "");
#endif

// GCC's register names.
register unsigned long current_stack_pointer asm("r15");
register void *global_pointer asm("gbr");

void registers(void) {
  register int a asm("r0");
  register int b asm("r14");
  register int c asm("fr12");
  register int d asm("sp");
  register int e asm("r16"); // expected-error {{unknown register name 'r16' in asm}}
  (void)a; (void)b; (void)c; (void)d; (void)e;
}

// The constraints of GCC's constraints.md, as the kernel uses them.
int constraints(int a, int *p) {
  int r, t;
  asm volatile("tst %1,%1\n\tmovt %0" : "=&z"(r) : "r"(a) : "t");
  asm volatile("mov.l @%1,%0" : "=r"(t) : "r"(p) : "memory");
  asm volatile("mul.l %0,%1" : : "r"(a), "r"(t) : "macl", "mach", "pr");
  asm volatile("add %1,%0" : "+r"(r) : "I08"(100));
  asm volatile("and %1,%0" : "+z"(r) : "K08"(200));
  asm volatile("mov.l %0,%1" : : "r"(a), "m"(*p));
  asm volatile("add %1,%0" : "+r"(r) : "I08"(1000)); // expected-error {{value '1000' out of range for constraint 'I08'}}
  asm volatile("nop" : : "Ixx"(1)); // expected-error {{invalid input constraint 'Ixx' in asm}}
  asm volatile("nop" : : : "r99"); // expected-error {{unknown register name 'r99' in asm}}
  return r + t + current_stack_pointer;
}
