// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-output=text -verify %s
// RUN: %clang_analyze_cc1 -triple i386-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-output=text -verify %s

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
  USBCombinedPacket *combined;
} USBPacket;

typedef struct USBDeviceClass {
  void (*handle_control)(USBDevice *, USBPacket *, int, int, int, int,
                         uint8_t *);
  void (*handle_data)(USBDevice *, USBPacket *);
} USBDeviceClass;

#line 1 "qemu-guest-memory-safety-usb-callback-catalog.c"
static int observed;

static void registered_control_oob( // expected-note {{USB callback parameter 'request' is guest-controlled}}
    USBDevice *dev, USBPacket *p, int request, int value, int index, int length,
    uint8_t *data) {
  int slots[4] = {0};
  observed = slots[request]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                             // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static void register_control_oob(ObjectClass *oc, const void *data) {
  USBDeviceClass *uc = (USBDeviceClass *)oc;
  uc->handle_control = registered_control_oob;
}

static const TypeInfo control_oob_type = {
    .name = "control-oob",
    .class_init = register_control_oob,
};

static void registered_control_value_oob( // expected-note {{USB callback parameter 'value' is guest-controlled}}
    USBDevice *dev, USBPacket *p, int request, int value, int index, int length,
    uint8_t *data) {
  int slots[4] = {0};
  observed = slots[value]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                           // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static void register_control_value_oob(ObjectClass *oc, const void *data) {
  USBDeviceClass *uc = (USBDeviceClass *)oc;
  uc->handle_control = registered_control_value_oob;
}

static const TypeInfo control_value_oob_type = {
    .name = "control-value-oob",
    .class_init = register_control_value_oob,
};

static void registered_control_index_oob( // expected-note {{USB callback parameter 'index' is guest-controlled}}
    USBDevice *dev, USBPacket *p, int request, int value, int index, int length,
    uint8_t *data) {
  int slots[4] = {0};
  observed = slots[index]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                           // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static void register_control_index_oob(ObjectClass *oc, const void *data) {
  USBDeviceClass *uc = (USBDeviceClass *)oc;
  uc->handle_control = registered_control_index_oob;
}

static const TypeInfo control_index_oob_type = {
    .name = "control-index-oob",
    .class_init = register_control_index_oob,
};

static void registered_control_length_oob( // expected-note {{USB callback parameter 'length' is guest-controlled}}
    USBDevice *dev, USBPacket *p, int request, int value, int index, int length,
    uint8_t *data) {
  int slots[4] = {0};
  observed = slots[length]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                            // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static void register_control_length_oob(ObjectClass *oc, const void *data) {
  USBDeviceClass *uc = (USBDeviceClass *)oc;
  uc->handle_control = registered_control_length_oob;
}

static const TypeInfo control_length_oob_type = {
    .name = "control-length-oob",
    .class_init = register_control_length_oob,
};

static void registered_data_oob( // expected-note {{USB callback parameter 'p.pid' is guest-controlled}}
    USBDevice *dev, USBPacket *p) {
  int slots[4] = {0};
  observed = slots[p->pid]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                            // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static void register_data_oob(ObjectClass *oc, const void *data) {
  USBDeviceClass *uc = (USBDeviceClass *)oc;
  uc->handle_data = registered_data_oob;
}

static const TypeInfo data_oob_type = {
    .name = "data-oob",
    .class_init = register_data_oob,
};

static void inherit_data_oob(ObjectClass *oc, const void *data) {
  /* The subclass deliberately inherits handle_data without reassigning it. */
}

static const TypeInfo inherited_data_oob_type = {
    .name = "inherited-data-oob",
    .parent = "data-oob",
    .class_init = inherit_data_oob,
};

static void repeat_data_oob_registration(ObjectClass *oc, const void *data) {
  USBDeviceClass *uc = (USBDeviceClass *)oc;
  uc->handle_data = registered_data_oob;
}

static const TypeInfo repeated_data_oob_type = {
    .name = "repeated-data-oob",
    .parent = "data-oob",
    .class_init = repeat_data_oob_registration,
};

static void registered_combined_capacity_oob( // expected-note {{USB callback parameter 'p.combined.iov.size' is guest-controlled}}
    USBDevice *dev, USBPacket *p) {
  int slots[4] = {0};
  observed = slots[p->combined->iov.size]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                                          // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static void register_combined_capacity_oob(ObjectClass *oc,
                                           const void *data) {
  USBDeviceClass *uc = (USBDeviceClass *)oc;
  uc->handle_data = registered_combined_capacity_oob;
}

static const TypeInfo combined_capacity_oob_type = {
    .name = "combined-capacity-oob",
    .class_init = register_combined_capacity_oob,
};

static void registered_capacity_selector_oob( // expected-note {{USB callback parameter 'p.combined' is guest-controlled}}
    USBDevice *dev, USBPacket *p) {
  int slots[4] = {0};
  observed = slots[(size_t)p->combined]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                                         // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static void register_capacity_selector_oob(ObjectClass *oc,
                                           const void *data) {
  USBDeviceClass *uc = (USBDeviceClass *)oc;
  uc->handle_data = registered_capacity_selector_oob;
}

static const TypeInfo capacity_selector_oob_type = {
    .name = "capacity-selector-oob",
    .class_init = register_capacity_selector_oob,
};

static void registered_primary_capacity_oob( // expected-note {{USB callback parameter 'p.iov.size' is guest-controlled}}
    USBDevice *dev, USBPacket *p) {
  int slots[4] = {0};
  observed = slots[p->iov.size]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                                 // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static void register_primary_capacity_oob(ObjectClass *oc,
                                          const void *data) {
  USBDeviceClass *uc = (USBDeviceClass *)oc;
  uc->handle_data = registered_primary_capacity_oob;
}

static const TypeInfo primary_capacity_oob_type = {
    .name = "primary-capacity-oob",
    .class_init = register_primary_capacity_oob,
};

static void registered_setup_parameter_oob( // expected-note {{USB callback parameter 'p.parameter' is guest-controlled}}
    USBDevice *dev, USBPacket *p) {
  int slots[4] = {0};
  observed = slots[p->parameter]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                                  // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static void register_setup_parameter_oob(ObjectClass *oc, const void *data) {
  USBDeviceClass *uc = (USBDeviceClass *)oc;
  uc->handle_data = registered_setup_parameter_oob;
}

static const TypeInfo setup_parameter_oob_type = {
    .name = "setup-parameter-oob",
    .class_init = register_setup_parameter_oob,
};

static void registered_endpoint_number_oob( // expected-note {{USB callback parameter 'p.ep.nr' is guest-controlled}}
    USBDevice *dev, USBPacket *p) {
  int slots[4] = {0};
  observed = slots[p->ep->nr]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                               // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static void register_endpoint_number_oob(ObjectClass *oc, const void *data) {
  USBDeviceClass *uc = (USBDeviceClass *)oc;
  uc->handle_data = registered_endpoint_number_oob;
}

static const TypeInfo endpoint_number_oob_type = {
    .name = "endpoint-number-oob",
    .class_init = register_endpoint_number_oob,
};

static void registered_endpoint_type_oob( // expected-note {{USB callback parameter 'p.ep.type' is guest-controlled}}
    USBDevice *dev, USBPacket *p) {
  int slots[4] = {0};
  observed = slots[p->ep->type]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                                 // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static void register_endpoint_type_oob(ObjectClass *oc, const void *data) {
  USBDeviceClass *uc = (USBDeviceClass *)oc;
  uc->handle_data = registered_endpoint_type_oob;
}

static const TypeInfo endpoint_type_oob_type = {
    .name = "endpoint-type-oob",
    .class_init = register_endpoint_type_oob,
};

static void guarded_control(USBDevice *dev, USBPacket *p, int request,
                            int value, int index, int length, uint8_t *data) {
  int slots[4] = {0};
  if ((unsigned)request >= 4)
    return;
  observed = slots[request];
}

static void register_guarded_control(ObjectClass *oc, const void *data) {
  USBDeviceClass *uc = (USBDeviceClass *)oc;
  uc->handle_control = guarded_control;
}

static const TypeInfo guarded_control_type = {
    .name = "guarded-control",
    .class_init = register_guarded_control,
};

static void guarded_data(USBDevice *dev, USBPacket *p) {
  int slots[4] = {0};
  if (p->iov.size >= 4)
    return;
  observed = slots[p->iov.size];
}

static void register_guarded_data(ObjectClass *oc, const void *data) {
  USBDeviceClass *uc = (USBDeviceClass *)oc;
  uc->handle_data = guarded_data;
}

static const TypeInfo guarded_data_type = {
    .name = "guarded-data",
    .class_init = register_guarded_data,
};
