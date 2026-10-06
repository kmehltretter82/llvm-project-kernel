// REQUIRES: x86-registered-target
// RUN: %clang_cc1 -triple x86_64-unknown-linux-gnu -fsyntax-only -verify %s
// RUN: %clang_cc1 -triple x86_64-unknown-linux-gnu -fsyntax-only \
// RUN:   -flinux-kernel-lenient-asm -verify=lenient %s

// lenient-no-diagnostics

// With -flinux-kernel-lenient-asm the frontend takes inline assembly as it
// is written where the description of the target does not know a
// constraint letter, a register name or an operand escape.  This is for
// checking code with -fsyntax-only for a target that clang describes
// incompletely: GCC accepts "%@" on m68k, for example.

register unsigned long frame asm("r99"); // expected-error {{unknown register name 'r99' in asm}}

unsigned long constraints(unsigned long a) {
  unsigned long r;

  asm("op %1, %0" : "=!" (r) : "r" (a)); // expected-error {{invalid output constraint '=!' in asm}}
  asm("op %1, %0" : "=r" (r) : "z" (a)); // expected-error {{invalid input constraint 'z' in asm}}
  return r;
}

void clobbers(void) {
  asm("nop" : : : "no_such_register"); // expected-error {{unknown register name 'no_such_register' in asm}}
}

void escapes(unsigned long a) {
  asm("jmp %@, %0" : : "r" (a)); // expected-error {{invalid % escape in inline assembly string}}
}

unsigned long local_register(void) {
  register unsigned long r asm("r98"); // expected-error {{unknown register name 'r98' in asm}}

  asm("" : "=r" (r));
  return r;
}
