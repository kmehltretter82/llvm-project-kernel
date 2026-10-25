// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -ftrivial-auto-var-init=uninitialized \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety -verify %s
// expected-no-diagnostics

typedef __SIZE_TYPE__ size_t;

typedef struct QEMUFile QEMUFile;

size_t qemu_get_buffer(QEMUFile *, unsigned char *, size_t);
void qemu_put_buffer(QEMUFile *, const unsigned char *, size_t);

void initialized_byte_prototype_is_disabled_by_default(QEMUFile *input,
                                                       QEMUFile *output) {
  unsigned char buffer[8];
  size_t bytes = qemu_get_buffer(input, buffer, sizeof(buffer));
  if (bytes != 4)
    return;
  qemu_put_buffer(output, buffer, sizeof(buffer));
}
