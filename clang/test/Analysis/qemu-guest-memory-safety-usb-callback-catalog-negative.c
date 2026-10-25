// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety -verify %s
// RUN: %clang_analyze_cc1 -triple i386-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety -verify %s
// expected-no-diagnostics

typedef __SIZE_TYPE__ size_t;
typedef __UINT8_TYPE__ uint8_t;
typedef __UINT64_TYPE__ uint64_t;

#line 1 "include/qom/object.h"
typedef struct ObjectClass {
  int unused;
} ObjectClass;

typedef struct TypeInfo {
  const char *name;
  const char *parent;
  void (*class_init)(ObjectClass *, const void *);
} TypeInfo;

#line 1 "include/qemu/iov.h"
typedef struct QEMUIOVector {
  void *iov;
  int niov;
  union {
    int nalloc;
    size_t size;
  };
} QEMUIOVector;

#line 1 "include/hw/usb/usb.h"
typedef struct USBDevice {
  int unused;
} USBDevice;

typedef struct USBEndpoint {
  uint8_t nr;
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
  uint8_t short_not_ok;
  uint8_t int_req;
  unsigned noise;
  USBCombinedPacket *combined;
} USBPacket;

typedef struct USBDeviceClass {
  void (*handle_control)(USBDevice *, USBPacket *, int, int, int, int,
                         uint8_t *);
  void (*handle_data)(USBDevice *, USBPacket *);
} USBDeviceClass;

#line 1 "qemu-guest-memory-safety-usb-callback-catalog-negative.c"
static int observed;

static void handle_control(USBDevice *dev, USBPacket *p, int request, int value,
                           int index, int length, uint8_t *data) {
  int slots[4] = {0};
  observed = slots[request];
}

static void unregistered_callback(USBDevice *dev, USBPacket *p, int request,
                                  int value, int index, int length,
                                  uint8_t *data) {
  int slots[4] = {0};
  observed = slots[value];
}

static void unregistered_class_init(ObjectClass *oc, const void *data) {
  USBDeviceClass *uc = (USBDeviceClass *)oc;
  uc->handle_control = unregistered_callback;
}

static void outside_root_callback(USBDevice *dev, USBPacket *p, int request,
                                  int value, int index, int length,
                                  uint8_t *data) {
  int slots[4] = {0};
  observed = slots[index];
}

void assignment_outside_class_init(USBDeviceClass *uc) {
  uc->handle_control = outside_root_callback;
}

static void helper_callback(USBDevice *dev, USBPacket *p, int request,
                            int value, int index, int length, uint8_t *data) {
  int slots[4] = {0};
  observed = slots[length];
}

static void assign_from_helper(USBDeviceClass *uc) {
  uc->handle_control = helper_callback;
}

static void helper_only_class_init(ObjectClass *oc, const void *data) {
  assign_from_helper((USBDeviceClass *)oc);
}

static const TypeInfo helper_only_type = {
    .name = "helper-only",
    .class_init = helper_only_class_init,
};

typedef struct UnrelatedClass {
  void (*handle_control)(USBDevice *, USBPacket *, int, int, int, int,
                         uint8_t *);
} UnrelatedClass;

static void unrelated_callback(USBDevice *dev, USBPacket *p, int request,
                               int value, int index, int length,
                               uint8_t *data) {
  int slots[4] = {0};
  observed = slots[request];
}

static void unrelated_class_init(ObjectClass *oc, const void *data) {
  UnrelatedClass *uc = (UnrelatedClass *)oc;
  uc->handle_control = unrelated_callback;
}

static const TypeInfo unrelated_type = {
    .name = "unrelated",
    .class_init = unrelated_class_init,
};

static int wrong_prototype_callback(USBDevice *dev, USBPacket *p, int request,
                                    int value, int index, int length,
                                    uint8_t *data) {
  int slots[4] = {0};
  return slots[request];
}

static void wrong_prototype_class_init(ObjectClass *oc, const void *data) {
  USBDeviceClass *uc = (USBDeviceClass *)oc;
  uc->handle_control =
      (void (*)(USBDevice *, USBPacket *, int, int, int, int, uint8_t *))
          wrong_prototype_callback;
}

static const TypeInfo wrong_prototype_type = {
    .name = "wrong-prototype",
    .class_init = wrong_prototype_class_init,
};

static void callback_behind_wrong_class_init(
    USBDevice *dev, USBPacket *p, int request, int value, int index, int length,
    uint8_t *data) {
  int slots[4] = {0};
  observed = slots[request];
}

static void wrong_class_init_prototype(ObjectClass *oc) {
  USBDeviceClass *uc = (USBDeviceClass *)oc;
  uc->handle_control = callback_behind_wrong_class_init;
}

static const TypeInfo wrong_class_init_type = {
    .name = "wrong-class-init",
    .class_init = (void (*)(ObjectClass *, const void *))
        wrong_class_init_prototype,
};

static void control_data_is_not_tainted(USBDevice *dev, USBPacket *p,
                                        int request, int value, int index,
                                        int length, uint8_t *data) {
  int slots[4] = {0};
  if (!(request & 0x8000))
    return;
  observed = slots[data[0]];
}

static void control_data_class_init(ObjectClass *oc, const void *data) {
  USBDeviceClass *uc = (USBDeviceClass *)oc;
  uc->handle_control = control_data_is_not_tainted;
}

static const TypeInfo control_data_type = {
    .name = "control-data",
    .class_init = control_data_class_init,
};

static void data_packet_is_not_blanket_tainted(USBDevice *dev, USBPacket *p) {
  int slots[4] = {0};
  observed = slots[p->status];
  observed = slots[p->actual_length];
  observed = slots[p->short_not_ok];
  observed = slots[p->int_req];
  observed = slots[p->noise];
  observed = slots[(size_t)p];
}

static void data_packet_class_init(ObjectClass *oc, const void *data) {
  USBDeviceClass *uc = (USBDeviceClass *)oc;
  uc->handle_data = data_packet_is_not_blanket_tainted;
}

static const TypeInfo data_packet_type = {
    .name = "data-packet",
    .class_init = data_packet_class_init,
};
