// RUN: %clang_cc1 -triple x86_64-unknown-linux-gnu -fsyntax-only \
// RUN:   -Wuninitialized -Wconditional-uninitialized -verify %s

// A local register variable with an assembler name stands for a machine
// register.  Reading it reads the register: this is how code written for
// GCC gets at the stack pointer or at a global pointer.

unsigned long stack_pointer(void) {
  register unsigned long sp asm("rsp");

  return sp;
}

unsigned long plain_register(void) {
  register unsigned long r; // expected-note {{initialize the variable 'r' to silence this warning}}

  return r; // expected-warning {{variable 'r' is uninitialized when used here}}
}
