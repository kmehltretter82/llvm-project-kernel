// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -verify %s

typedef __UINT8_TYPE__ uint8_t;
typedef __INT8_TYPE__ int8_t;
typedef __INT32_TYPE__ int32_t;
typedef __UINT64_TYPE__ uint64_t;
typedef __SIZE_TYPE__ size_t;

void *memset(void *, int, size_t);

typedef struct USBDevice {
  uint8_t setup_buf[8];
  uint8_t data_buf[64];
  int32_t setup_len;
  int32_t setup_index;
} USBDevice;

void vulnerable_parent_shape(USBDevice *device) {
  device->setup_len = (device->setup_buf[7] << 8) |
                      device->setup_buf[6];
  if (device->setup_len > sizeof(device->data_buf))
    return; // expected-warning {{Level B: guest-controlled USB setup length state may exceed the host object extent}}
}

void fixed_shape(USBDevice *device) {
  unsigned length =
      (device->setup_buf[7] << 8) | device->setup_buf[6];
  if (length > sizeof(device->data_buf))
    return;
  device->setup_len = length;
}

void exact_capacity(USBDevice *device) {
  int length = (device->setup_buf[7] << 8) | device->setup_buf[6];
  if (length != sizeof(device->data_buf))
    return;
  device->setup_len = length;
}

void one_past_capacity(USBDevice *device) {
  int length = (device->setup_buf[7] << 8) | device->setup_buf[6];
  if (length != sizeof(device->data_buf) + 1)
    return;
  device->setup_len = length; // expected-warning {{Level A: guest-controlled USB setup length state exceeds the host object extent}}
}

void masked_length(USBDevice *device) {
  device->setup_len =
      ((device->setup_buf[7] << 8) | device->setup_buf[6]) & 63;
}

void clamped_length(USBDevice *device) {
  int length = (device->setup_buf[7] << 8) | device->setup_buf[6];
  if (length > sizeof(device->data_buf))
    length = sizeof(device->data_buf);
  device->setup_len = length;
}

void trusted_assignment(USBDevice *device, int length) {
  device->setup_len = length;
}

void negative_length(USBDevice *device) {
  if (device->setup_buf[6] != 1)
    return;
  device->setup_len = -device->setup_buf[6]; // expected-warning {{Level A: guest-controlled USB setup length state is negative}}
}

void narrowing_cast_can_be_negative(USBDevice *device) {
  if (device->setup_buf[6] != 255)
    return;
  device->setup_len = (int8_t)device->setup_buf[6]; // expected-warning {{Level A: guest-controlled USB setup length state is negative}}
}

void truncating_conversion_stores_zero(USBDevice *device) {
  uint64_t length = ((uint64_t)device->setup_buf[6]) << 32;
  device->setup_len = length;
}

void reassigned_low_bits_can_be_unsafe(USBDevice *device) {
  uint64_t length = ((uint64_t)device->setup_buf[7]) << 32;
  length = device->setup_buf[6];
  if (length != sizeof(device->data_buf) + 1)
    return;
  device->setup_len = length; // expected-warning {{Level A: guest-controlled USB setup length state exceeds the host object extent}}
}

void repaired_before_escape(USBDevice *device) {
  device->setup_len = (device->setup_buf[7] << 8) |
                      device->setup_buf[6];
  device->setup_len = 0;
}

void repaired_by_object_reset(USBDevice *device) {
  device->setup_len = (device->setup_buf[7] << 8) |
                      device->setup_buf[6];
  memset(device, 0, sizeof(*device));
}

void repaired_by_aggregate_reset(USBDevice *device) {
  device->setup_len = (device->setup_buf[7] << 8) |
                      device->setup_buf[6];
  *device = (USBDevice){0};
}

void aggregate_copy_preserves_invalid_state(USBDevice devices[2]) {
  devices[0].setup_len = (devices[0].setup_buf[7] << 8) |
                         devices[0].setup_buf[6];
  devices[1] = devices[0];
  devices[0].setup_len = 0; // expected-warning {{Level B: guest-controlled USB setup length state may exceed the host object extent}}
}

void reset_other_array_element(USBDevice devices[2]) {
  devices[0].setup_len = (devices[0].setup_buf[7] << 8) |
                         devices[0].setup_buf[6];
  memset(&devices[1], 0, sizeof(devices[1])); // expected-warning {{Level B: guest-controlled USB setup length state may exceed the host object extent}}
}

static unsigned setup_length_from_helper(USBDevice *device) {
  return (device->setup_buf[7] << 8) | device->setup_buf[6];
}

void validated_helper_return(USBDevice *device) {
  unsigned length = setup_length_from_helper(device);
  if (length > sizeof(device->data_buf))
    return;
  device->setup_len = length;
}

static void helper_leaves_invalid_state(USBDevice *device) {
  device->setup_len = (device->setup_buf[7] << 8) |
                      device->setup_buf[6];
}

void helper_then_repair(USBDevice *device) {
  helper_leaves_invalid_state(device);
  device->setup_len = 0;
}

typedef struct OtherUSBDevice {
  uint8_t setup_buf[8];
  uint8_t data_buf[4096];
  int32_t setup_len;
} OtherUSBDevice;

void unrelated_record(OtherUSBDevice *device) {
  device->setup_len =
      (device->setup_buf[7] << 8) | device->setup_buf[6];
}

void unrelated_field(USBDevice *device) {
  device->setup_index =
      (device->setup_buf[7] << 8) | device->setup_buf[6];
}
