// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.MigrationConsistency \
// RUN:   -verify=noopt %s
// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.MigrationConsistency \
// RUN:   -analyzer-config alpha.qemu.MigrationConsistency:EnableInlineVArrayDiagnostics=true \
// RUN:   -verify=noopt %s
// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.MigrationConsistency \
// RUN:   -analyzer-config alpha.qemu.MigrationConsistency:EnableFlexibleVArrayDiagnostics=true \
// RUN:   -verify=flex %s
// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.MigrationConsistency \
// RUN:   -analyzer-config alpha.qemu.MigrationConsistency:EnableFlexibleVArrayDiagnostics=true \
// RUN:   %s 2>&1 | FileCheck %s --check-prefix=FLEX-MESSAGES
// RUN: %clang_analyze_cc1 -triple i386-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.MigrationConsistency \
// RUN:   -verify=noopt %s
// RUN: %clang_analyze_cc1 -triple i386-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.MigrationConsistency \
// RUN:   -analyzer-config alpha.qemu.MigrationConsistency:EnableFlexibleVArrayDiagnostics=true \
// RUN:   -verify=flex %s

// noopt-no-diagnostics
// FLEX-MESSAGES: [qemu.migration-flex-varray-capacity] migration version 1 loads count 'size' with maximum 255 before flexible array 'contents'; registered capacities {16, 64, 128, 256} include unsafe capacities {16, 64, 128}, and no applicable equality validation preserves the allocation bound
// FLEX-MESSAGES: [qemu.migration-flex-varray-capacity] migration version 1 loads count 'size' with maximum 255 before flexible array 'contents'; registered capacities {254} include unsafe capacities {254}, and no applicable equality validation preserves the allocation bound
// FLEX-MESSAGES: [qemu.migration-flex-varray-capacity] migration version 1 loads count 'size' with maximum 255 before flexible array 'contents'; registered capacities {64} include unsafe capacities {64}, and no applicable equality validation preserves the allocation bound
// FLEX-MESSAGES: [qemu.migration-flex-varray-capacity] migration version 1 loads count 'size' with maximum 255 before flexible array 'contents'; registered capacities {64} include unsafe capacities {64}, and no applicable equality validation preserves the allocation bound

typedef __SIZE_TYPE__ size_t;
typedef _Bool bool;
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;

typedef struct QEMUFile QEMUFile;
typedef struct VMStateIf VMStateIf;
typedef struct VMStateField VMStateField;
typedef struct VMStateDescription VMStateDescription;

struct VMStateInfo {
  const char *name;
  int (*get)(QEMUFile *, void *, size_t, const VMStateField *);
};
typedef struct VMStateInfo VMStateInfo;

typedef struct VMStateStructMember {
  size_t offset;
  uint8_t size;
} VMStateStructMember;

enum VMStateFlags {
  VMS_SINGLE = 0x001,
  VMS_POINTER = 0x002,
  VMS_ARRAY = 0x004,
  VMS_STRUCT = 0x008,
  VMS_VARRAY = 0x010,
  VMS_BUFFER = 0x020,
  VMS_NO_STATE = 0x080,
  VMS_END = 0x200,
  VMS_MUST_EXIST = 0x1000,
};

struct VMStateField {
  const char *name;
  size_t offset;
  size_t size;
  VMStateStructMember size_indirect;
  VMStateStructMember num_indirect;
  size_t start;
  int num;
  const VMStateInfo *info;
  enum VMStateFlags flags;
  const VMStateDescription *vmsd;
  int version_id;
  int struct_version_id;
  bool (*field_exists)(void *, int);
};

struct VMStateDescription {
  const char *name;
  bool unmigratable;
  int version_id;
  int minimum_version_id;
  int (*pre_load)(void *);
  bool (*pre_load_errp)(void *, void **);
  const VMStateField *fields;
};

unsigned int qemu_get_ubyte(QEMUFile *f);
void *g_malloc0(size_t size);
int vmstate_register_any(VMStateIf *obj, const VMStateDescription *vmsd,
                         void *opaque);
void fallback_marker(void);
void mutate_state(void *state);
void escape_state(void *address);

#define vmstate_offset_value(_state, _field, _type) \
  __builtin_offsetof(_state, _field)
#define vmstate_field_offset(_state, _field)                            \
  {                                                                    \
    .offset = __builtin_offsetof(_state, _field),                       \
    .size = sizeof(((_state *)0)->_field),                              \
  }
#define VMSTATE_SINGLE_TEST(_field, _state, _test, _version, _info, _type) \
  {                                                                         \
    .name = #_field, .offset = vmstate_offset_value(_state, _field, _type), \
    .size = sizeof(_type), .info = &(_info), .flags = VMS_SINGLE,           \
    .version_id = (_version), .field_exists = (_test),                      \
  }
#define VMSTATE_UINT16_HACK_TEST(_field, _state, _test)                  \
  VMSTATE_SINGLE_TEST(_field, _state, _test, 0,                          \
                      vmstate_hack_uint16_from_uint8, uint16_t)
#define VMSTATE_UINT16_EQUAL_TEST(_field, _state, _test, _version)       \
  VMSTATE_SINGLE_TEST(_field, _state, _test, _version,                   \
                      vmstate_info_uint16_equal, uint16_t)
#define VMSTATE_UINT16_EQUAL_V(_field, _state, _version)                 \
  VMSTATE_UINT16_EQUAL_TEST(_field, _state, 0, _version)
#define VMSTATE_UINT32_HACK_TEST(_field, _state, _test)                  \
  VMSTATE_SINGLE_TEST(_field, _state, _test, 0,                          \
                      vmstate_hack_uint32_from_uint8, uint32_t)
#define VMSTATE_UNUSED_TEST(_test, _size)                                \
  {                                                                      \
    .name = "unused", .size = (_size),                                  \
    .info = &vmstate_info_unused_buffer, .flags = VMS_BUFFER,            \
    .field_exists = (_test),                                             \
  }
#define VMSTATE_VARRAY_UINT16_UNSAFE(_field, _state, _count, _version)   \
  {                                                                      \
    .name = #_field, .offset = __builtin_offsetof(_state, _field),       \
    .size = sizeof(uint16_t),                                             \
    .num_indirect = vmstate_field_offset(_state, _count),                 \
    .info = &vmstate_info_uint16, .flags = VMS_VARRAY,                    \
    .version_id = (_version),                                             \
  }
#define VMSTATE_VARRAY_UINT32_UNSAFE(_field, _state, _count, _version)   \
  {                                                                      \
    .name = #_field, .offset = __builtin_offsetof(_state, _field),       \
    .size = sizeof(uint16_t),                                             \
    .num_indirect = vmstate_field_offset(_state, _count),                 \
    .info = &vmstate_info_uint16, .flags = VMS_VARRAY,                    \
    .version_id = (_version),                                             \
  }
#define VMSTATE_VALIDATE(_name, _test)                                   \
  {                                                                      \
    .name = (_name), .field_exists = (_test),                            \
    .flags = VMS_MUST_EXIST | VMS_NO_STATE,                              \
  }
#define VMSTATE_LEGACY_VALIDATE(_test)                                   \
  {                                                                      \
    .name = "legacy validator", .num = 0,                               \
    .flags = VMS_ARRAY | VMS_MUST_EXIST, .field_exists = (_test),        \
  }
#define VMSTATE_END_OF_LIST()                                             \
  {                                                                      \
    .flags = VMS_END,                                                     \
  }

static const VMStateInfo vmstate_info_uint16;
static const VMStateInfo vmstate_info_uint16_equal;
static const VMStateInfo vmstate_info_unused_buffer;

static int get_uint16_from_uint8(QEMUFile *f, void *pv, size_t size,
                                 const VMStateField *field) {
  uint16_t *v = pv;
  *v = qemu_get_ubyte(f);
  return 0;
}

static int get_uint16_masked(QEMUFile *f, void *pv, size_t size,
                             const VMStateField *field) {
  uint16_t *v = pv;
  *v = qemu_get_ubyte(f) & 7;
  return 0;
}

static int get_uint32_from_uint8(QEMUFile *f, void *pv, size_t size,
                                 const VMStateField *field) {
  uint32_t *v = pv;
  *v = qemu_get_ubyte(f);
  return 0;
}

static const VMStateInfo vmstate_hack_uint16_from_uint8 = {
    .name = "uint16 from uint8",
    .get = get_uint16_from_uint8,
};

static const VMStateInfo vmstate_masked_uint16_from_uint8 = {
    .name = "masked uint16 from uint8",
    .get = get_uint16_masked,
};

static const VMStateInfo vmstate_hack_uint32_from_uint8 = {
    .name = "uint32 from uint8",
    .get = get_uint32_from_uint8,
};

enum {
  OLD_VERSION = 1,
  CURRENT_VERSION = 2,
};

static bool is_old_version(void *opaque, int version_id) {
  return version_id == OLD_VERSION;
}

static bool opaque_old_version(void *opaque, int version_id) {
  return version_id == OLD_VERSION && opaque != 0;
}

static bool count_validator(void *opaque, int version_id) {
  return opaque != 0 && version_id >= OLD_VERSION;
}

static int pre_load_hook(void *opaque) { return 0; }

typedef struct FlexState {
  uint16_t size;
  uint16_t contents[];
} FlexState;

typedef struct FlexSideState {
  uint16_t side;
  uint16_t size;
  uint16_t contents[];
} FlexSideState;

typedef struct Flex32State {
  uint32_t size;
  uint16_t contents[];
} Flex32State;

static const VMStateDescription mixed_description = {
    .name = "mixed",
    .version_id = CURRENT_VERSION,
    .minimum_version_id = OLD_VERSION,
    .fields = (const VMStateField[]){
        VMSTATE_UINT16_HACK_TEST(size, FlexState, is_old_version),
        VMSTATE_UNUSED_TEST(is_old_version, 1),
        VMSTATE_UINT16_EQUAL_V(size, FlexState, CURRENT_VERSION),
        VMSTATE_VARRAY_UINT16_UNSAFE(contents, FlexState, size, 0), // flex-warning {{migration version 1 loads count 'size'}}
        VMSTATE_END_OF_LIST(),
    },
};

static const VMStateDescription boundary_254_description = {
    .name = "boundary-254",
    .version_id = CURRENT_VERSION,
    .minimum_version_id = OLD_VERSION,
    .fields = (const VMStateField[]){
        VMSTATE_UINT16_HACK_TEST(size, FlexState, is_old_version),
        VMSTATE_VARRAY_UINT16_UNSAFE(contents, FlexState, size, 0), // flex-warning {{migration version 1 loads count 'size'}}
        VMSTATE_END_OF_LIST(),
    },
};

static const VMStateDescription boundary_255_description = {
    .name = "boundary-255",
    .version_id = CURRENT_VERSION,
    .minimum_version_id = OLD_VERSION,
    .fields = (const VMStateField[]){
        VMSTATE_UINT16_HACK_TEST(size, FlexState, is_old_version),
        VMSTATE_VARRAY_UINT16_UNSAFE(contents, FlexState, size, 0),
        VMSTATE_END_OF_LIST(),
    },
};

static const VMStateDescription equal_after_load_description = {
    .name = "equal-after-load",
    .version_id = CURRENT_VERSION,
    .minimum_version_id = OLD_VERSION,
    .fields = (const VMStateField[]){
        VMSTATE_UINT16_HACK_TEST(size, FlexState, is_old_version),
        VMSTATE_UINT16_EQUAL_TEST(size, FlexState, is_old_version, 0),
        VMSTATE_VARRAY_UINT16_UNSAFE(contents, FlexState, size, 0), // flex-warning {{migration version 1 loads count 'size'}}
        VMSTATE_END_OF_LIST(),
    },
};

static const VMStateDescription unsupported_getter_description = {
    .name = "unsupported-getter",
    .version_id = CURRENT_VERSION,
    .minimum_version_id = OLD_VERSION,
    .fields = (const VMStateField[]){
        VMSTATE_SINGLE_TEST(size, FlexState, is_old_version, 0,
                            vmstate_masked_uint16_from_uint8, uint16_t),
        VMSTATE_VARRAY_UINT16_UNSAFE(contents, FlexState, size, 0),
        VMSTATE_END_OF_LIST(),
    },
};

static const VMStateDescription opaque_predicate_description = {
    .name = "opaque-predicate",
    .version_id = CURRENT_VERSION,
    .minimum_version_id = OLD_VERSION,
    .fields = (const VMStateField[]){
        VMSTATE_UINT16_HACK_TEST(size, FlexState, opaque_old_version),
        VMSTATE_VARRAY_UINT16_UNSAFE(contents, FlexState, size, 0),
        VMSTATE_END_OF_LIST(),
    },
};

static const VMStateDescription validator_before_description = {
    .name = "validator-before",
    .version_id = CURRENT_VERSION,
    .minimum_version_id = OLD_VERSION,
    .fields = (const VMStateField[]){
        VMSTATE_UINT16_HACK_TEST(size, FlexState, is_old_version),
        VMSTATE_VALIDATE("count validator", count_validator),
        VMSTATE_VARRAY_UINT16_UNSAFE(contents, FlexState, size, 0),
        VMSTATE_END_OF_LIST(),
    },
};

static const VMStateDescription validator_after_description = {
    .name = "validator-after",
    .version_id = CURRENT_VERSION,
    .minimum_version_id = OLD_VERSION,
    .fields = (const VMStateField[]){
        VMSTATE_UINT16_HACK_TEST(size, FlexState, is_old_version),
        VMSTATE_VARRAY_UINT16_UNSAFE(contents, FlexState, size, 0), // flex-warning {{migration version 1 loads count 'size'}}
        VMSTATE_VALIDATE("late validator", count_validator),
        VMSTATE_END_OF_LIST(),
    },
};

static const VMStateDescription array_before_load_description = {
    .name = "array-before-load",
    .version_id = CURRENT_VERSION,
    .minimum_version_id = OLD_VERSION,
    .fields = (const VMStateField[]){
        VMSTATE_VARRAY_UINT16_UNSAFE(contents, FlexState, size, 0),
        VMSTATE_UINT16_HACK_TEST(size, FlexState, is_old_version),
        VMSTATE_END_OF_LIST(),
    },
};

static const VMStateDescription bad_allocation_description = {
    .name = "bad-allocation",
    .version_id = CURRENT_VERSION,
    .minimum_version_id = OLD_VERSION,
    .fields = (const VMStateField[]){
        VMSTATE_UINT16_HACK_TEST(size, FlexState, is_old_version),
        VMSTATE_VARRAY_UINT16_UNSAFE(contents, FlexState, size, 0),
        VMSTATE_END_OF_LIST(),
    },
};

static const VMStateDescription open_switch_description = {
    .name = "open-switch",
    .version_id = CURRENT_VERSION,
    .minimum_version_id = OLD_VERSION,
    .fields = (const VMStateField[]){
        VMSTATE_UINT16_HACK_TEST(size, FlexState, is_old_version),
        VMSTATE_VARRAY_UINT16_UNSAFE(contents, FlexState, size, 0),
        VMSTATE_END_OF_LIST(),
    },
};

static const VMStateDescription pre_load_description = {
    .name = "pre-load",
    .version_id = CURRENT_VERSION,
    .minimum_version_id = OLD_VERSION,
    .pre_load = pre_load_hook,
    .fields = (const VMStateField[]){
        VMSTATE_UINT16_HACK_TEST(size, FlexState, is_old_version),
        VMSTATE_VARRAY_UINT16_UNSAFE(contents, FlexState, size, 0),
        VMSTATE_END_OF_LIST(),
    },
};

static const VMStateDescription legacy_validator_description = {
    .name = "legacy-validator",
    .version_id = CURRENT_VERSION,
    .minimum_version_id = OLD_VERSION,
    .fields = (const VMStateField[]){
        VMSTATE_UINT16_HACK_TEST(size, FlexState, is_old_version),
        VMSTATE_LEGACY_VALIDATE(is_old_version),
        VMSTATE_VARRAY_UINT16_UNSAFE(contents, FlexState, size, 0),
        VMSTATE_END_OF_LIST(),
    },
};

static const VMStateDescription unrelated_getter_description = {
    .name = "unrelated-getter",
    .version_id = CURRENT_VERSION,
    .minimum_version_id = OLD_VERSION,
    .fields = (const VMStateField[]){
        VMSTATE_UINT16_HACK_TEST(size, FlexSideState, is_old_version),
        VMSTATE_SINGLE_TEST(side, FlexSideState, 0, 0,
                            vmstate_hack_uint16_from_uint8, uint16_t),
        VMSTATE_VARRAY_UINT16_UNSAFE(contents, FlexSideState, size, 0),
        VMSTATE_END_OF_LIST(),
    },
};

static const VMStateDescription product_overflow_description = {
    .name = "product-overflow",
    .version_id = CURRENT_VERSION,
    .minimum_version_id = OLD_VERSION,
    .fields = (const VMStateField[]){
        VMSTATE_UINT32_HACK_TEST(size, Flex32State, is_old_version),
        VMSTATE_VARRAY_UINT32_UNSAFE(contents, Flex32State, size, 0),
        VMSTATE_END_OF_LIST(),
    },
};

#define CONTROL_FLOW_DESCRIPTION(_variable, _name)                     \
  static const VMStateDescription _variable = {                        \
      .name = (_name),                                                  \
      .version_id = CURRENT_VERSION,                                    \
      .minimum_version_id = OLD_VERSION,                                \
      .fields = (const VMStateField[]){                                 \
          VMSTATE_UINT16_HACK_TEST(size, FlexState, is_old_version),    \
          VMSTATE_VARRAY_UINT16_UNSAFE(contents, FlexState, size, 0),   \
          VMSTATE_END_OF_LIST(),                                        \
      },                                                                \
  }

CONTROL_FLOW_DESCRIPTION(conditional_assignment_description,
                         "conditional-assignment");
CONTROL_FLOW_DESCRIPTION(conditional_registration_description,
                         "conditional-registration");
CONTROL_FLOW_DESCRIPTION(unknown_call_description, "unknown-call");
CONTROL_FLOW_DESCRIPTION(address_escape_description, "address-escape");
CONTROL_FLOW_DESCRIPTION(indirect_registration_description,
                         "indirect-registration");

typedef struct __attribute__((aligned(8))) PaddedState {
  uint8_t prefix[10];
  uint16_t size;
  uint16_t contents[];
} PaddedState;

static const VMStateDescription padded_description = {
    .name = "padded",
    .version_id = CURRENT_VERSION,
    .minimum_version_id = OLD_VERSION,
    .fields = (const VMStateField[]){
        VMSTATE_UINT16_HACK_TEST(size, PaddedState, is_old_version),
        VMSTATE_VARRAY_UINT16_UNSAFE(contents, PaddedState, size, 0),
        VMSTATE_END_OF_LIST(),
    },
};

static FlexState *new_mixed(uint16_t nwords) {
  FlexState *state;
  switch (nwords) {
  case 16:
  case 64:
    break;
  case 128:
  case 256:
    break;
  default:
    fallback_marker();
    nwords = 64;
  }
  state = g_malloc0(sizeof(*state) + nwords * 2);
  state->size = nwords;
  vmstate_register_any(0, &mixed_description, state);
  return state;
}

static FlexState *new_boundary_254(uint16_t nwords) {
  FlexState *state;
  switch (nwords) {
  case 254:
    break;
  default:
    fallback_marker();
    nwords = 254;
  }
  state = g_malloc0(sizeof(*state) + nwords * 2);
  state->size = nwords;
  vmstate_register_any(0, &boundary_254_description, state);
  return state;
}

static FlexState *new_boundary_255(uint16_t nwords) {
  FlexState *state;
  switch (nwords) {
  case 255:
    break;
  default:
    fallback_marker();
    nwords = 255;
  }
  state = g_malloc0(sizeof(*state) + nwords * 2);
  state->size = nwords;
  vmstate_register_any(0, &boundary_255_description, state);
  return state;
}

static FlexState *new_equal_after_load(uint16_t nwords) {
  FlexState *state;
  switch (nwords) {
  case 64:
    break;
  default:
    fallback_marker();
    nwords = 64;
  }
  state = g_malloc0(sizeof(*state) + nwords * 2);
  state->size = nwords;
  vmstate_register_any(0, &equal_after_load_description, state);
  return state;
}

static FlexState *new_unsupported_getter(uint16_t nwords) {
  FlexState *state;
  switch (nwords) {
  case 4:
    break;
  default:
    fallback_marker();
    nwords = 4;
  }
  state = g_malloc0(sizeof(*state) + nwords * 2);
  state->size = nwords;
  vmstate_register_any(0, &unsupported_getter_description, state);
  return state;
}

static FlexState *new_opaque_predicate(uint16_t nwords) {
  FlexState *state;
  switch (nwords) {
  case 4:
    break;
  default:
    fallback_marker();
    nwords = 4;
  }
  state = g_malloc0(sizeof(*state) + nwords * 2);
  state->size = nwords;
  vmstate_register_any(0, &opaque_predicate_description, state);
  return state;
}

static FlexState *new_validator_before(uint16_t nwords) {
  FlexState *state;
  switch (nwords) {
  case 64:
    break;
  default:
    fallback_marker();
    nwords = 64;
  }
  state = g_malloc0(sizeof(*state) + nwords * 2);
  state->size = nwords;
  vmstate_register_any(0, &validator_before_description, state);
  return state;
}

static FlexState *new_validator_after(uint16_t nwords) {
  FlexState *state;
  switch (nwords) {
  case 64:
    break;
  default:
    fallback_marker();
    nwords = 64;
  }
  state = g_malloc0(sizeof(*state) + nwords * 2);
  state->size = nwords;
  vmstate_register_any(0, &validator_after_description, state);
  return state;
}

static FlexState *new_array_before_load(uint16_t nwords) {
  FlexState *state;
  switch (nwords) {
  case 64:
    break;
  default:
    fallback_marker();
    nwords = 64;
  }
  state = g_malloc0(sizeof(*state) + nwords * 2);
  state->size = nwords;
  vmstate_register_any(0, &array_before_load_description, state);
  return state;
}

static FlexState *new_bad_allocation(uint16_t nwords) {
  FlexState *state;
  switch (nwords) {
  case 64:
    break;
  default:
    fallback_marker();
    nwords = 64;
  }
  state = g_malloc0(sizeof(*state) + nwords);
  state->size = nwords;
  vmstate_register_any(0, &bad_allocation_description, state);
  return state;
}

static FlexState *new_open_switch(uint16_t nwords) {
  FlexState *state;
  switch (nwords) {
  case 64:
    break;
  }
  state = g_malloc0(sizeof(*state) + nwords * 2);
  state->size = nwords;
  vmstate_register_any(0, &open_switch_description, state);
  return state;
}

static FlexState *new_pre_load(uint16_t nwords) {
  FlexState *state;
  switch (nwords) {
  case 64:
    break;
  default:
    fallback_marker();
    nwords = 64;
  }
  state = g_malloc0(sizeof(*state) + nwords * 2);
  state->size = nwords;
  vmstate_register_any(0, &pre_load_description, state);
  return state;
}

static PaddedState *new_padded(uint16_t nwords) {
  PaddedState *state;
  switch (nwords) {
  case 253:
    break;
  default:
    fallback_marker();
    nwords = 253;
  }
  state = g_malloc0(sizeof(*state) + nwords * 2);
  state->size = nwords;
  vmstate_register_any(0, &padded_description, state);
  return state;
}

static FlexState *new_legacy_validator(uint16_t nwords) {
  FlexState *state;
  switch (nwords) {
  case 64:
    break;
  default:
    fallback_marker();
    nwords = 64;
  }
  state = g_malloc0(sizeof(*state) + nwords * 2);
  state->size = nwords;
  vmstate_register_any(0, &legacy_validator_description, state);
  return state;
}

static FlexSideState *new_unrelated_getter(uint16_t nwords) {
  FlexSideState *state;
  switch (nwords) {
  case 64:
    break;
  default:
    fallback_marker();
    nwords = 64;
  }
  state = g_malloc0(sizeof(*state) + nwords * 2);
  state->size = nwords;
  vmstate_register_any(0, &unrelated_getter_description, state);
  return state;
}

static FlexState *new_conditional_assignment(uint16_t nwords, bool enabled) {
  FlexState *state;
  switch (nwords) {
  case 64:
    break;
  default:
    fallback_marker();
    nwords = 64;
  }
  state = g_malloc0(sizeof(*state) + nwords * 2);
  if (enabled) {
    state->size = nwords;
  }
  vmstate_register_any(0, &conditional_assignment_description, state);
  return state;
}

static FlexState *new_conditional_registration(uint16_t nwords, bool enabled) {
  FlexState *state;
  switch (nwords) {
  case 64:
    break;
  default:
    fallback_marker();
    nwords = 64;
  }
  state = g_malloc0(sizeof(*state) + nwords * 2);
  state->size = nwords;
  if (enabled) {
    vmstate_register_any(0, &conditional_registration_description, state);
  }
  return state;
}

static FlexState *new_unknown_call(uint16_t nwords) {
  FlexState *state;
  switch (nwords) {
  case 64:
    break;
  default:
    fallback_marker();
    nwords = 64;
  }
  state = g_malloc0(sizeof(*state) + nwords * 2);
  state->size = nwords;
  mutate_state(state);
  vmstate_register_any(0, &unknown_call_description, state);
  return state;
}

static FlexState *new_address_escape(uint16_t nwords) {
  FlexState *state;
  switch (nwords) {
  case 64:
    break;
  default:
    fallback_marker();
    nwords = 64;
  }
  state = g_malloc0(sizeof(*state) + nwords * 2);
  state->size = nwords;
  escape_state(&state);
  vmstate_register_any(0, &address_escape_description, state);
  return state;
}

typedef int (*RegisterFunction)(VMStateIf *, const VMStateDescription *,
                                void *);

static FlexState *new_indirect_registration(uint16_t nwords) {
  FlexState *state;
  RegisterFunction register_function = vmstate_register_any;
  switch (nwords) {
  case 64:
    break;
  default:
    fallback_marker();
    nwords = 64;
  }
  state = g_malloc0(sizeof(*state) + nwords * 2);
  state->size = nwords;
  register_function(0, &indirect_registration_description, state);
  return state;
}

static Flex32State *new_product_overflow(uint32_t nwords) {
  Flex32State *state;
  switch (nwords) {
  case 64:
  case 0x80000000U:
    break;
  default:
    fallback_marker();
    nwords = 64;
  }
  state = g_malloc0(sizeof(*state) + nwords * 2U);
  state->size = nwords;
  vmstate_register_any(0, &product_overflow_description, state);
  return state;
}
