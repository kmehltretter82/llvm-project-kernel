// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.qemu.GuestInput -analyzer-config optin.taint.TaintPropagation:Config=%S/Inputs/qemu-guest-taint.yaml -verify %s

typedef __UINT64_TYPE__ uint64_t;
typedef struct QEMUFile QEMUFile;

unsigned qemu_get_byte(QEMUFile *f);

uint64_t unbounded_shift(QEMUFile *f) {
  unsigned shift = qemu_get_byte(f);
  return (uint64_t)1 << shift; // expected-warning {{guest-controlled shift amount is not bounded}}
}

uint64_t bounded_shift(QEMUFile *f) {
  unsigned shift = qemu_get_byte(f);
  if (shift >= 64)
    return 0;
  return (uint64_t)1 << shift;
}

#define SHIFT_BY(value, amount) ((uint64_t)(value) << (amount))

uint64_t macro_shift(QEMUFile *f) {
  unsigned shift = qemu_get_byte(f);
  return SHIFT_BY(1, shift); // expected-warning {{guest-controlled shift amount is not bounded}}
}

unsigned (*indirect_reader)(QEMUFile *);

uint64_t indirect_source_is_conservative(QEMUFile *f) {
  unsigned shift = indirect_reader(f);
  return (uint64_t)1 << shift;
}

__attribute__((suppress)) uint64_t suppressed_shift(QEMUFile *f) {
  unsigned shift = qemu_get_byte(f);
  return (uint64_t)1 << shift;
}
