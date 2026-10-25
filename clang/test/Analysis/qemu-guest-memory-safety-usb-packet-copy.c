// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -ftrivial-auto-var-init=uninitialized -DG_DISABLE_CHECKS \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:EnableInitializedByteTracking=true \
// RUN:   -verify %s
// RUN: %clang_analyze_cc1 -triple i386-unknown-linux-gnu \
// RUN:   -ftrivial-auto-var-init=uninitialized -DG_DISABLE_CHECKS \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
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
  USB_TOKEN_IN = 0x69,
  USB_TOKEN_OUT = 0xe1,
};

void usb_packet_copy(USBPacket *, void *, size_t);

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

void direct_short_copy_is_valid(USBPacket *packet) {
  unsigned char buffer[3];
  USBEndpoint endpoint;
  set_direct_packet_metadata(packet, &endpoint, 8);
  packet->actual_length = 2;
  usb_packet_copy(packet, buffer, sizeof(buffer));
}

void combined_exact_boundary_is_valid(USBPacket *packet) {
  unsigned char buffer[1];
  USBEndpoint endpoint;
  USBCombinedPacket combined;
  endpoint.type = 2;
  combined.iov.size = 8;
  packet->pid = USB_TOKEN_OUT;
  packet->ep = &endpoint;
  packet->iov.size = 1;
  packet->parameter = 0;
  packet->status = 0;
  packet->actual_length = 7;
  packet->combined = &combined;
  usb_packet_copy(packet, buffer, sizeof(buffer));
}

void negative_actual_length_is_rejected(USBPacket *packet) {
  unsigned char buffer[1];
  USBEndpoint endpoint;
  set_direct_packet_metadata(packet, &endpoint, 8);
  packet->actual_length = -1;
  usb_packet_copy(packet, buffer, sizeof(buffer));
  // expected-warning@-1 {{Level A: USB packet actual_length is negative}}
}

void direct_range_beyond_capacity_is_rejected(USBPacket *packet) {
  unsigned char buffer[2];
  USBEndpoint endpoint;
  set_direct_packet_metadata(packet, &endpoint, 8);
  packet->actual_length = 7;
  usb_packet_copy(packet, buffer, sizeof(buffer));
  // expected-warning@-1 {{Level A: USB packet copy range exceeds the selected direct iovec capacity}}
}

void combined_range_beyond_capacity_is_rejected(USBPacket *packet) {
  unsigned char buffer[2];
  USBEndpoint endpoint;
  USBCombinedPacket combined;
  endpoint.type = 2;
  combined.iov.size = 8;
  packet->pid = USB_TOKEN_OUT;
  packet->ep = &endpoint;
  packet->iov.size = 64;
  packet->parameter = 0;
  packet->status = 0;
  packet->actual_length = 7;
  packet->combined = &combined;
  usb_packet_copy(packet, buffer, sizeof(buffer));
  // expected-warning@-1 {{Level A: USB packet copy range exceeds the selected combined iovec capacity}}
}

void addition_wrap_is_rejected(USBPacket *packet) {
  unsigned char buffer[1];
  USBEndpoint endpoint;
  size_t maximum = (size_t)-1;
  size_t bytes = maximum - (size_t)2147483647 + 1;
  set_direct_packet_metadata(packet, &endpoint, maximum);
  packet->actual_length = 2147483647;
  usb_packet_copy(packet, buffer, bytes);
  // expected-warning@-1 {{Level A: USB packet copy range exceeds the selected direct iovec capacity}}
}

void actual_length_destination_boundary_is_valid(USBPacket *packet) {
  unsigned char buffer[1];
  USBEndpoint endpoint;
  set_direct_packet_metadata(packet, &endpoint, (size_t)-1);
  packet->actual_length = 2147483646;
  usb_packet_copy(packet, buffer, sizeof(buffer));
}

void actual_length_destination_overflow_is_rejected(USBPacket *packet) {
  unsigned char buffer[1];
  USBEndpoint endpoint;
  set_direct_packet_metadata(packet, &endpoint, (size_t)-1);
  packet->actual_length = 2147483647;
  usb_packet_copy(packet, buffer, sizeof(buffer));
  // expected-warning@-1 {{Level A: USB packet actual_length update exceeds its destination type}}
}

void in_direction_range_violation_is_rejected(USBPacket *packet) {
  unsigned char buffer[2] = {0, 0};
  USBEndpoint endpoint;
  set_direct_packet_metadata(packet, &endpoint, 8);
  packet->pid = USB_TOKEN_IN;
  packet->actual_length = 7;
  usb_packet_copy(packet, buffer, sizeof(buffer));
  // expected-warning@-1 {{Level A: USB packet copy range exceeds the selected direct iovec capacity}}
}

void zero_bytes_at_capacity_is_valid(USBPacket *packet) {
  unsigned char buffer[1];
  USBEndpoint endpoint;
  set_direct_packet_metadata(packet, &endpoint, 8);
  packet->actual_length = 8;
  usb_packet_copy(packet, buffer, 0);
}

void zero_bytes_beyond_capacity_is_rejected(USBPacket *packet) {
  unsigned char buffer[1];
  USBEndpoint endpoint;
  set_direct_packet_metadata(packet, &endpoint, 8);
  packet->actual_length = 9;
  usb_packet_copy(packet, buffer, 0);
  // expected-warning@-1 {{Level A: USB packet copy range exceeds the selected direct iovec capacity}}
}

void repeated_copies_advance_actual_length(USBPacket *packet) {
  unsigned char buffer[4];
  USBEndpoint endpoint;
  set_direct_packet_metadata(packet, &endpoint, 8);
  packet->actual_length = 0;
  usb_packet_copy(packet, buffer, sizeof(buffer));

  // The opaque declaration would normally invalidate packet fields.  Restore
  // the fields usb_packet_copy() preserves, but deliberately do not restore
  // actual_length: the model must have advanced it from zero to four.
  set_direct_packet_metadata(packet, &endpoint, 8);
  usb_packet_copy(packet, buffer, sizeof(buffer));

  set_direct_packet_metadata(packet, &endpoint, 8);
  usb_packet_copy(packet, buffer, 1);
  // expected-warning@-1 {{Level A: USB packet copy range exceeds the selected direct iovec capacity}}
}

void unknown_capacity_selector_is_not_reported(
    USBPacket *packet, USBCombinedPacket *maybe_combined) {
  unsigned char buffer[1];
  USBEndpoint endpoint;
  endpoint.type = 2;
  packet->pid = USB_TOKEN_OUT;
  packet->ep = &endpoint;
  packet->iov.size = 8;
  packet->parameter = 0;
  packet->status = 0;
  packet->actual_length = 0;
  packet->combined = maybe_combined;
  usb_packet_copy(packet, buffer, sizeof(buffer));
}

void symbolic_copy_width_is_not_reported(USBPacket *packet, size_t bytes) {
  unsigned char buffer[8];
  USBEndpoint endpoint;
  set_direct_packet_metadata(packet, &endpoint, sizeof(buffer));
  packet->actual_length = 0;
  usb_packet_copy(packet, buffer, bytes);
}

void unresolved_copy_does_not_leave_stale_actual_length(USBPacket *packet,
                                                         size_t bytes) {
  unsigned char buffer[5];
  USBEndpoint endpoint;
  set_direct_packet_metadata(packet, &endpoint, 8);
  packet->actual_length = 0;
  usb_packet_copy(packet, buffer, 4);

  set_direct_packet_metadata(packet, &endpoint, 8);
  usb_packet_copy(packet, buffer, bytes);

  // The unresolved middle operation invalidates actual_length.  A later call
  // must not reuse the first operation's stale value of four.
  set_direct_packet_metadata(packet, &endpoint, 8);
  usb_packet_copy(packet, buffer, sizeof(buffer));
}
