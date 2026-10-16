// RUN: %clang_cc1 -triple riscv64-unknown-linux-gnu -fsyntax-only \
// RUN:   -verify %s

#if !__has_builtin(__builtin_riscv_linux_irq_site)
#error RISC-V Linux IRQ site builtin is unavailable
#endif

void valid_sites(void) {
  __builtin_riscv_linux_irq_site(1, 0);
  __builtin_riscv_linux_irq_site(39, 65535);
}

void invalid_sites(unsigned int kind, unsigned int ordinal) {
  __builtin_riscv_linux_irq_site(0, 0); // expected-error {{argument value 0 is outside the valid range [1, 39]}}
  __builtin_riscv_linux_irq_site(40, 0); // expected-error {{argument value 40 is outside the valid range [1, 39]}}
  __builtin_riscv_linux_irq_site(1, 65536); // expected-error {{argument value 65536 is outside the valid range [0, 65535]}}
  __builtin_riscv_linux_irq_site(kind, 0); // expected-error {{must be a constant integer}}
  __builtin_riscv_linux_irq_site(1, ordinal); // expected-error {{must be a constant integer}}
}
