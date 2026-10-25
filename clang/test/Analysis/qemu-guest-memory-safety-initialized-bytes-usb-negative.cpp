// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -ftrivial-auto-var-init=uninitialized \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:EnableInitializedByteTracking=true \
// RUN:   -verify %s
// RUN: %clang_analyze_cc1 -triple i386-unknown-linux-gnu \
// RUN:   -ftrivial-auto-var-init=uninitialized \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:EnableInitializedByteTracking=true \
// RUN:   -verify %s
// expected-no-diagnostics

using size_t = __SIZE_TYPE__;

struct QEMUFile;
size_t qemu_get_buffer(QEMUFile *, unsigned char *, size_t);
void qemu_put_buffer(QEMUFile *, const unsigned char *, size_t);

struct USBPacket {
  int pid;
};

void usb_packet_copy(USBPacket *, unsigned char *, size_t);

void same_name_is_not_enough(QEMUFile *input, QEMUFile *output,
                             USBPacket *packet) {
  unsigned char buffer[8];
  size_t bytes = qemu_get_buffer(input, buffer, sizeof(buffer));
  if (bytes != 4)
    return;
  packet->pid = 0x69;
  usb_packet_copy(packet, buffer, sizeof(buffer));
  qemu_put_buffer(output, buffer, sizeof(buffer));
}
