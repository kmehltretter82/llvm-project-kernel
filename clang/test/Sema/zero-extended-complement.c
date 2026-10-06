// RUN: %clang_cc1 -triple x86_64-unknown-linux-gnu -fsyntax-only \
// RUN:   -Wzero-extended-complement -verify %s
// RUN: %clang_cc1 -triple i386-unknown-linux-gnu -fsyntax-only \
// RUN:   -Wzero-extended-complement -verify=expected,ilp32 %s
// RUN: %clang_cc1 -triple x86_64-unknown-linux-gnu -fsyntax-only -Wall \
// RUN:   -Wextra -verify=wall %s

// wall-no-diagnostics

typedef unsigned int u32;
typedef unsigned long long u64;

#define FLAG 0x10U
#define BIT(n) (1UL << (n))

// The complement of a 32-bit unsigned value has no bits above bit 31.

u64 clear(u64 v) {
  return v & ~FLAG; // expected-warning {{'~' is applied to a 32-bit unsigned value and the result is zero-extended to 64 bits, so this '&' clears the upper 32 bits of the other operand}}
}

void clear_in_place(u64 *v, u32 mask) {
  *v &= ~mask; // expected-warning {{'~' is applied to a 32-bit unsigned value and the result is zero-extended to 64 bits, so this '&=' clears the upper 32 bits of the other operand}}
}

u64 reversed(u64 v, u32 mask) {
  return ~mask & v; // expected-warning {{'~' is applied to a 32-bit unsigned value}}
}

int test(u64 v, u32 mask) {
  if (v & ~mask) // expected-warning {{'~' is applied to a 32-bit unsigned value}}
    return 1;
  return 0;
}

// unsigned long is 64 bits wide on x86_64 and 32 bits wide on i386: the
// same line is right on one and wrong on the other.
u64 clear_bit3(u64 v) {
  return v & ~BIT(3); // ilp32-warning {{'~' is applied to a 32-bit unsigned value and the result is zero-extended to 64 bits}}
}

// A signed complement is sign-extended and keeps the upper bits.
u64 fine_signed(u64 v) { return v & ~0x10; }

u64 fine_wide(u64 v) { return v & ~0x10ULL; }

u64 fine_cast(u64 v, u32 mask) { return v & ~(u64)mask; }

// The result is cut down to the width of the mask anyway.
u32 fine_narrow(u64 v) { return v & ~FLAG; }

void fine_narrow_store(u32 *out, u64 v, u32 mask) { *out = v & ~mask; }

// The other operand has no upper bits.
u64 fine_small(u32 a) { return (u64)a & ~FLAG; }

u64 fine_constant(u32 mask) { return 0xffULL & ~mask; }

// "~0U" says that 32 bits are meant.
u64 low_half(u64 v) { return v & ~0U; }

// The complement is kept in a variable: it is computed in the width of the
// variable, and the '&' widens what the variable holds.  Only for
// "unsigned long", whose width depends on the machine.
u64 mask_in_long(u64 addr, unsigned long size) {
  unsigned long mask = ~(size - 1); // ilp32-note {{'mask' gets the complement here}}

  return addr & mask; // ilp32-warning {{'~' is applied to a 32-bit unsigned value and the result is zero-extended to 64 bits, so this '&' clears the upper 32 bits of the other operand}}
}

void mask_in_long_assign(u64 *addr, unsigned long size) {
  const unsigned long mask = ~(size - 1); // ilp32-note {{'mask' gets the complement here}}

  *addr &= mask; // ilp32-warning {{'~' is applied to a 32-bit unsigned value and the result is zero-extended to 64 bits, so this '&=' clears the upper 32 bits of the other operand}}
}

// A variable of exactly 32 bits says how many bits are meant.
u64 mask_in_u32(u64 val, u32 shift) {
  u32 mask = ~(0xffu << shift);

  val &= mask;
  return val;
}

// One of two values: nothing is known about the variable.
u64 mask_one_of_two(u64 addr, u32 size, int aligned) {
  u32 mask = 0xff;

  if (aligned)
    mask = ~(size - 1);
  return addr & mask;
}

// The variable is wide enough.
u64 fine_mask_variable(u64 addr, u32 size) {
  u64 mask = ~(u64)(size - 1);

  return addr & mask;
}
