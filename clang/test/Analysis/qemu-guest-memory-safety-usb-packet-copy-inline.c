// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -ftrivial-auto-var-init=uninitialized -DG_DISABLE_CHECKS \
// RUN:   -analyzer-checker=core,debug.ExprInspection,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config ipa=inlining \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:EnableInitializedByteTracking=true \
// RUN:   -verify %s
// RUN: %clang_analyze_cc1 -triple i386-unknown-linux-gnu \
// RUN:   -ftrivial-auto-var-init=uninitialized -DG_DISABLE_CHECKS \
// RUN:   -analyzer-checker=core,debug.ExprInspection,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config ipa=inlining \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:EnableInitializedByteTracking=true \
// RUN:   -verify %s

typedef __SIZE_TYPE__ size_t;
typedef __UINT8_TYPE__ uint8_t;
typedef __UINT64_TYPE__ uint64_t;

typedef struct QEMUIOVector {
  size_t size;
} QEMUIOVector;

typedef struct USBEndpoint {
  uint8_t type;
} USBEndpoint;

typedef struct USBCombinedPacket {
  QEMUIOVector iov;
} USBCombinedPacket;

typedef struct USBPacket {
  int pid;
  USBEndpoint *ep;
  QEMUIOVector iov;
  uint64_t parameter;
  int status;
  int actual_length;
  USBCombinedPacket *combined;
} USBPacket;

enum {
  USB_TOKEN_OUT = 0xe1,
};

void clang_analyzer_eval(int);

void usb_packet_copy(USBPacket *packet, void *buffer, size_t bytes) {
  (void)buffer;
  packet->actual_length += bytes;
}

static void set_direct_packet_metadata(USBPacket *packet,
                                       USBEndpoint *endpoint,
                                       size_t capacity) {
  endpoint->type = 2;
  packet->pid = USB_TOKEN_OUT;
  packet->ep = endpoint;
  packet->iov.size = capacity;
  packet->parameter = 0;
  packet->status = 0;
  packet->combined = 0;
}

void inlined_body_and_summary_advance_once(USBPacket *packet) {
  unsigned char buffer[4];
  USBEndpoint endpoint;
  set_direct_packet_metadata(packet, &endpoint, 8);
  packet->actual_length = 0;
  usb_packet_copy(packet, buffer, 2);
  clang_analyzer_eval(packet->actual_length == 2); // expected-warning {{TRUE}}

  set_direct_packet_metadata(packet, &endpoint, 8);
  usb_packet_copy(packet, buffer, 2);
  clang_analyzer_eval(packet->actual_length == 4); // expected-warning {{TRUE}}

  set_direct_packet_metadata(packet, &endpoint, 8);
  usb_packet_copy(packet, buffer, 4);
  clang_analyzer_eval(packet->actual_length == 8); // expected-warning {{TRUE}}

  set_direct_packet_metadata(packet, &endpoint, 8);
  usb_packet_copy(packet, buffer, 1);
  // expected-warning@-1 {{Level A: USB packet copy range exceeds the selected direct iovec capacity}}
}
