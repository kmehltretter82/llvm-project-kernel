// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-output=text -verify %s
// RUN: %clang_analyze_cc1 -triple i386-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-output=text -verify %s

typedef __SIZE_TYPE__ size_t;
typedef __UINT8_TYPE__ uint8_t;

void *memcpy(void *, const void *, size_t);

#line 1 "include/qom/object.h"
typedef struct ObjectClass {
  int unused;
} ObjectClass;

typedef struct TypeInfo {
  const char *name;
  void (*class_init)(ObjectClass *, const void *);
} TypeInfo;

#line 1 "include/hw/usb/usb.h"
typedef struct USBDevice {
  int unused;
} USBDevice;

typedef struct USBPacket {
  int actual_length;
} USBPacket;

typedef struct USBDeviceClass {
  void (*handle_control)(USBDevice *, USBPacket *, int, int, int, int,
                         uint8_t *);
} USBDeviceClass;

#line 1 "qemu-guest-memory-safety-usb-control-buffer.c"
static int observed;

enum {
  USB_CONTROL_IN = 0x8000,
};

#define REGISTER_CONTROL(FN)                                                \
  static void FN##_class_init(ObjectClass *oc, const void *opaque) {        \
    USBDeviceClass *uc = (USBDeviceClass *)oc;                              \
    uc->handle_control = FN;                                                 \
  }                                                                         \
  static const TypeInfo FN##_type = {                                       \
      .name = #FN,                                                          \
      .class_init = FN##_class_init,                                        \
  }

static void control_read_maybe( // expected-note {{USB callback parameter 'length' is guest-controlled}}
    USBDevice *dev, USBPacket *p, int request, int value, int index,
    int length, uint8_t *data) {
  observed = data[1]; // expected-warning {{Level B: USB callback buffer read may exceed the available guest-input bytes}}
                      // expected-note@-1 {{Level B: USB callback buffer read may exceed the available guest-input bytes}}
}
REGISTER_CONTROL(control_read_maybe);

static void control_read_definite( // expected-note {{USB callback parameter 'length' is guest-controlled}}
    USBDevice *dev, USBPacket *p, int request, int value, int index,
    int length, uint8_t *data) {
  observed = data[length]; // expected-warning {{Level A: USB callback buffer read exceeds the available guest-input bytes}}
                           // expected-note@-1 {{Level A: USB callback buffer read exceeds the available guest-input bytes}}
}
REGISTER_CONTROL(control_read_definite);

static void control_copy_definite( // expected-note {{USB callback parameter 'length' is guest-controlled}}
    USBDevice *dev, USBPacket *p, int request, int value, int index,
    int length, uint8_t *data) {
  uint8_t byte;
  memcpy(&byte, data + length, 1); // expected-warning {{Level A: USB callback buffer read exceeds the available guest-input bytes}}
                                  // expected-note@-1 {{Level A: USB callback buffer read exceeds the available guest-input bytes}}
}
REGISTER_CONTROL(control_copy_definite);

static void control_narrowed_offset_maybe( // expected-note {{USB callback parameter 'length' is guest-controlled}}
    USBDevice *dev, USBPacket *p, int request, int value, int index,
    int length, uint8_t *data) {
  observed = data[(uint8_t)length]; // expected-warning {{Level B: USB callback buffer read may exceed the available guest-input bytes}}
                                     // expected-note@-1 {{Level B: USB callback buffer read may exceed the available guest-input bytes}}
}
REGISTER_CONTROL(control_narrowed_offset_maybe);

static void control_read_guarded(USBDevice *dev, USBPacket *p, int request,
                                 int value, int index, int length,
                                 uint8_t *data) {
  if (length <= 1)
    return;
  observed = data[1];
}
REGISTER_CONTROL(control_read_guarded);

static void control_copy_guarded(USBDevice *dev, USBPacket *p, int request,
                                 int value, int index, int length,
                                 uint8_t *data) {
  uint8_t destination[8];
  if (length < (int)sizeof(destination))
    return;
  memcpy(destination, data, sizeof(destination));
}
REGISTER_CONTROL(control_copy_guarded);

static void control_zero_width_at_end(USBDevice *dev, USBPacket *p,
                                      int request, int value, int index,
                                      int length, uint8_t *data) {
  uint8_t byte;
  memcpy(&byte, data + length, 0);
}
REGISTER_CONTROL(control_zero_width_at_end);

static void control_out_bytes_are_input(
    USBDevice *dev, USBPacket *p, int request, int value, int index,
    int length, uint8_t *data) {
  int slots[4] = {0};
  if (request & USB_CONTROL_IN) // expected-note {{Assuming the condition is false}} expected-note {{Taking false branch}}
    return;
  if (length <= 0) // expected-note {{Assuming 'length' is > 0}} expected-note {{Taking false branch}}
    return;
  observed = slots[data[0]]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                             // expected-note@-1 {{USB callback parameter 'data' is guest-controlled}}
                             // expected-note@-2 {{Level B: guest-controlled array index may exceed the host object element count}}
}
REGISTER_CONTROL(control_out_bytes_are_input);

static void control_in_bytes_are_not_input(
    USBDevice *dev, USBPacket *p, int request, int value, int index,
    int length, uint8_t *data) {
  int slots[4] = {0};
  if (!(request & USB_CONTROL_IN))
    return;
  if (length <= 0)
    return;
  observed = slots[data[0]];
}
REGISTER_CONTROL(control_in_bytes_are_not_input);

static void control_pointer_is_not_input(
    USBDevice *dev, USBPacket *p, int request, int value, int index,
    int length, uint8_t *data) {
  int slots[4] = {0};
  observed = slots[(size_t)data];
}
REGISTER_CONTROL(control_pointer_is_not_input);

static void control_negative_length_does_not_wrap(
    USBDevice *dev, USBPacket *p, int request, int value, int index,
    int length, uint8_t *data) {
  if (length >= 0)
    return;
  observed = data[0];
}
REGISTER_CONTROL(control_negative_length_does_not_wrap);

static void control_in_write_beyond_wlength_is_staging_safe(
    USBDevice *dev, USBPacket *p, int request, int value, int index,
    int length, uint8_t *data) {
  if (!(request & USB_CONTROL_IN))
    return;
  if (length != 1)
    return;
  data[3] = 0;
  p->actual_length = 4;
}
REGISTER_CONTROL(control_in_write_beyond_wlength_is_staging_safe);

static void unregistered_control_buffer(
    USBDevice *dev, USBPacket *p, int request, int value, int index,
    int length, uint8_t *data) {
  observed = data[length];
}

static void wrong_buffer_order(USBDevice *dev, USBPacket *p, int request,
                               int value, int index, uint8_t *data,
                               int length) {
  observed = data[length];
}

static void wrong_buffer_order_class_init(ObjectClass *oc,
                                          const void *opaque) {
  USBDeviceClass *uc = (USBDeviceClass *)oc;
  uc->handle_control =
      (void (*)(USBDevice *, USBPacket *, int, int, int, int, uint8_t *))
          wrong_buffer_order;
}

static const TypeInfo wrong_buffer_order_type = {
    .name = "wrong-buffer-order",
    .class_init = wrong_buffer_order_class_init,
};
