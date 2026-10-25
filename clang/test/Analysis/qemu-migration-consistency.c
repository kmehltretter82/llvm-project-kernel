// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.MigrationConsistency \
// RUN:   -verify=expected %s
// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.MigrationConsistency \
// RUN:   -analyzer-config alpha.qemu.MigrationConsistency:EnableInlineVArrayDiagnostics=true \
// RUN:   -verify=expected,inline %s
// RUN: %clang_analyze_cc1 -triple i386-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.MigrationConsistency \
// RUN:   -verify=expected %s
// RUN: %clang_analyze_cc1 -triple i386-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.MigrationConsistency \
// RUN:   -analyzer-config alpha.qemu.MigrationConsistency:EnableInlineVArrayDiagnostics=true \
// RUN:   -verify=expected,inline %s

typedef __SIZE_TYPE__ size_t;
typedef _Bool bool;

typedef struct VMStateInfo {
  const char *name;
} VMStateInfo;

typedef struct VMStateField {
  const char *name;
  size_t offset;
  size_t size;
  struct {
    size_t offset;
    unsigned char size;
  } num_indirect;
  unsigned flags;
  const VMStateInfo *info;
  int version_id;
  bool (*field_exists)(void *, int);
} VMStateField;

typedef struct VMStateDescription {
  const char *name;
  int version_id;
  int minimum_version_id;
  const VMStateField *fields;
} VMStateDescription;

static bool optional_field(void *opaque, int version_id) {
  return version_id >= 9;
}

#define VMSTATE_FIELD(_name, _version)                                      \
  { .name = (_name), .version_id = (_version) }
#define VMSTATE_FIELD_TEST(_name, _version, _test)                          \
  { .name = (_name), .version_id = (_version), .field_exists = (_test) }
#define VMSTATE_END_OF_LIST() {}

enum {
  VMS_SINGLE = 0x001,
  VMS_POINTER = 0x002,
  VMS_STRUCT = 0x008,
  VMS_VARRAY = 0x010,
  VMS_NO_STATE = 0x080,
  VMS_MUST_EXIST = 0x1000,
  VMS_ALLOC = 0x2000,
};

static const VMStateInfo vmstate_info_uint8;
static const VMStateInfo vmstate_info_uint32;
static const VMStateInfo vmstate_info_uint32_equal;
static const VMStateInfo vmstate_info_custom;
static const VMStateInfo vmstate_info_fake_equal;

#define MEMBER_OFFSET(_state, _field)                                      \
  {                                                                         \
    .offset = __builtin_offsetof(_state, _field),                           \
    .size = sizeof(((_state *)0)->_field),                                  \
  }
#define VMSTATE_UINT8(_field, _state)                                       \
  {                                                                         \
    .name = #_field, .offset = __builtin_offsetof(_state, _field),          \
    .size = sizeof(unsigned char), .info = &vmstate_info_uint8,             \
    .flags = VMS_SINGLE                                                     \
  }
#define VMSTATE_UINT32(_field, _state)                                      \
  {                                                                         \
    .name = #_field, .offset = __builtin_offsetof(_state, _field),          \
    .size = sizeof(unsigned), .info = &vmstate_info_uint32,                 \
    .flags = VMS_SINGLE                                                     \
  }
#define VMSTATE_UINT32_V(_field, _state, _version)                          \
  {                                                                         \
    .name = #_field, .offset = __builtin_offsetof(_state, _field),          \
    .size = sizeof(unsigned), .info = &vmstate_info_uint32,                 \
    .version_id = (_version), .flags = VMS_SINGLE                           \
  }
#define VMSTATE_UINT32_TEST(_field, _state, _test)                          \
  {                                                                         \
    .name = #_field, .offset = __builtin_offsetof(_state, _field),          \
    .size = sizeof(unsigned), .info = &vmstate_info_uint32,                 \
    .field_exists = (_test), .flags = VMS_SINGLE                            \
  }
#define VMSTATE_UINT32_CUSTOM(_field, _state)                               \
  {                                                                         \
    .name = #_field, .offset = __builtin_offsetof(_state, _field),          \
    .size = sizeof(unsigned), .info = &vmstate_info_custom,                 \
    .flags = VMS_SINGLE                                                     \
  }
#define VMSTATE_UINT32_FAKE_EQUAL(_field, _state)                           \
  {                                                                         \
    .name = #_field, .offset = __builtin_offsetof(_state, _field),          \
    .size = sizeof(unsigned),                                               \
    .info = __builtin_choose_expr(1, &vmstate_info_uint32,                  \
                                  &vmstate_info_fake_equal),                 \
    .flags = VMS_SINGLE                                                     \
  }
#define VMSTATE_UINT32_EQUAL(_field, _state)                                \
  {                                                                         \
    .name = #_field, .offset = __builtin_offsetof(_state, _field),          \
    .size = sizeof(unsigned), .info = &vmstate_info_uint32_equal,           \
    .flags = VMS_SINGLE                                                     \
  }
#define VMSTATE_STRUCT_VARRAY_UINT32(_field, _state, _count)                \
  {                                                                         \
    .name = #_field, .offset = __builtin_offsetof(_state, _field),          \
    .size = sizeof(((_state *)0)->_field[0]),                               \
    .num_indirect = MEMBER_OFFSET(_state, _count),                          \
    .flags = VMS_STRUCT | VMS_VARRAY                                       \
  }
#define VMSTATE_STRUCT_VARRAY_UINT32_V(_field, _state, _count, _version)    \
  {                                                                         \
    .name = #_field, .offset = __builtin_offsetof(_state, _field),          \
    .size = sizeof(((_state *)0)->_field[0]),                               \
    .num_indirect = MEMBER_OFFSET(_state, _count),                          \
    .version_id = (_version), .flags = VMS_STRUCT | VMS_VARRAY              \
  }
#define VMSTATE_STRUCT_VARRAY_UINT32_TEST(_field, _state, _count, _test)    \
  {                                                                         \
    .name = #_field, .offset = __builtin_offsetof(_state, _field),          \
    .size = sizeof(((_state *)0)->_field[0]),                               \
    .num_indirect = MEMBER_OFFSET(_state, _count),                          \
    .field_exists = (_test), .flags = VMS_STRUCT | VMS_VARRAY               \
  }
#define VMSTATE_STRUCT_VARRAY_POINTER_UINT32(_field, _state, _count)        \
  {                                                                         \
    .name = #_field, .offset = __builtin_offsetof(_state, _field),          \
    .size = sizeof(((_state *)0)->_field[0]),                               \
    .num_indirect = MEMBER_OFFSET(_state, _count),                          \
    .flags = VMS_STRUCT | VMS_VARRAY | VMS_POINTER | VMS_ALLOC             \
  }
#define VMSTATE_VALIDATE(_test)                                             \
  {                                                                         \
    .name = "validate", .field_exists = (_test),                           \
    .flags = VMS_MUST_EXIST | VMS_NO_STATE                                 \
  }

static const VMStateDescription bad_range = {
    .name = "bad-range",
    .version_id = 2,
    .minimum_version_id = 3, // expected-warning {{accepts minimum version 3 but advertises maximum version 2}}
    .fields = (const VMStateField[]){VMSTATE_END_OF_LIST()},
};

static const VMStateDescription unreachable_field = {
    .name = "unreachable-field",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]){
        VMSTATE_FIELD("late", 2), // expected-warning {{migration field requires version 2, but containing VMStateDescription 'unreachable_field' only writes version 1; this field can never be present}}
        VMSTATE_END_OF_LIST(),
    },
};

static const VMStateDescription valid_fields = {
    .name = "valid-fields",
    .version_id = 2,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]){
        VMSTATE_FIELD("old", 1),
        VMSTATE_FIELD("current", 2),
        VMSTATE_FIELD_TEST("predicate-controls-presence", 9, optional_field),
        VMSTATE_END_OF_LIST(),
    },
};

static const VMStateField named_unreachable_fields[] = {
    VMSTATE_FIELD("late", 3), // expected-warning {{migration field requires version 3, but containing VMStateDescription 'named_unreachable_field' only writes version 2; this field can never be present}}
    VMSTATE_END_OF_LIST(),
};

static const VMStateDescription named_unreachable_field = {
    .name = "named-unreachable-field",
    .version_id = 2,
    .minimum_version_id = 1,
    .fields = named_unreachable_fields,
};

typedef struct HostDependentState {
  void *pointer;
} HostDependentState;

static const VMStateDescription abi_dependent_version = {
    .name = "abi-dependent",
    .version_id = sizeof(HostDependentState), // expected-warning {{derives version_id from sizeof; migration versions must not depend on host ABI layout}}
    .minimum_version_id = 1,
    .fields = (const VMStateField[]){VMSTATE_END_OF_LIST()},
};

static const VMStateDescription explicitly_suppressed
    __attribute__((suppress)) = {
        .name = "suppressed",
        .version_id = 1,
        .minimum_version_id = 1,
        .fields = (const VMStateField[]){
            VMSTATE_FIELD("late", 2),
            VMSTATE_END_OF_LIST(),
        },
};

typedef struct InlineArrayState {
  unsigned count;
  unsigned unrelated;
  unsigned entries[4];
} InlineArrayState;

static const VMStateDescription unbounded_inline_array = {
    .name = "unbounded-inline-array",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]){
        VMSTATE_UINT32(count, InlineArrayState),
        VMSTATE_STRUCT_VARRAY_UINT32(entries, InlineArrayState, count), // inline-warning {{qemu.migration-inline-varray-count}}
        VMSTATE_END_OF_LIST(),
    },
};

static const VMStateField named_unbounded_fields[] = {
    VMSTATE_UINT32(count, InlineArrayState),
    VMSTATE_STRUCT_VARRAY_UINT32(entries, InlineArrayState, count), // inline-warning {{qemu.migration-inline-varray-count}}
    VMSTATE_END_OF_LIST(),
};

static const VMStateDescription named_unbounded_inline_array = {
    .name = "named-unbounded-inline-array",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = named_unbounded_fields,
};

static bool count_is_valid(void *opaque, int version_id) {
  InlineArrayState *state = opaque;
  return state->count <= 4;
}

static const VMStateDescription validation_barrier = {
    .name = "validation-barrier",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]){
        VMSTATE_UINT32(count, InlineArrayState),
        VMSTATE_VALIDATE(count_is_valid),
        VMSTATE_STRUCT_VARRAY_UINT32(entries, InlineArrayState, count),
        VMSTATE_END_OF_LIST(),
    },
};

static bool unrelated_is_valid(void *opaque, int version_id) {
  InlineArrayState *state = opaque;
  return state->unrelated <= 4;
}

static const VMStateDescription unrelated_validation = {
    .name = "unrelated-validation",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]){
        VMSTATE_UINT32(count, InlineArrayState),
        VMSTATE_VALIDATE(unrelated_is_valid),
        VMSTATE_STRUCT_VARRAY_UINT32(entries, InlineArrayState, count), // inline-warning {{qemu.migration-inline-varray-count}}
        VMSTATE_END_OF_LIST(),
    },
};

static const VMStateDescription late_validation = {
    .name = "late-validation",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]){
        VMSTATE_UINT32(count, InlineArrayState),
        VMSTATE_STRUCT_VARRAY_UINT32(entries, InlineArrayState, count), // inline-warning {{qemu.migration-inline-varray-count}}
        VMSTATE_VALIDATE(count_is_valid),
        VMSTATE_END_OF_LIST(),
    },
};

static const VMStateDescription equal_count_is_not_loaded = {
    .name = "equal-count",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]){
        VMSTATE_UINT32_EQUAL(count, InlineArrayState),
        VMSTATE_STRUCT_VARRAY_UINT32(entries, InlineArrayState, count),
        VMSTATE_END_OF_LIST(),
    },
};

static const VMStateDescription equal_check_does_not_erase_prior_load = {
    .name = "equal-after-load",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]){
        VMSTATE_UINT32(count, InlineArrayState),
        VMSTATE_UINT32_EQUAL(count, InlineArrayState),
        VMSTATE_STRUCT_VARRAY_UINT32(entries, InlineArrayState, count), // inline-warning {{qemu.migration-inline-varray-count}}
        VMSTATE_END_OF_LIST(),
    },
};

static const VMStateDescription fake_equal_name_is_not_trusted = {
    .name = "fake-equal-name",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]){
        VMSTATE_UINT32_FAKE_EQUAL(count, InlineArrayState),
        VMSTATE_STRUCT_VARRAY_UINT32(entries, InlineArrayState, count), // inline-warning {{qemu.migration-inline-varray-count}}
        VMSTATE_END_OF_LIST(),
    },
};

static const VMStateDescription custom_loader_is_unsupported = {
    .name = "custom-loader",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]){
        VMSTATE_UINT32_CUSTOM(count, InlineArrayState),
        VMSTATE_STRUCT_VARRAY_UINT32(entries, InlineArrayState, count),
        VMSTATE_END_OF_LIST(),
    },
};

static const VMStateDescription count_loaded_after_array = {
    .name = "count-loaded-after-array",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]){
        VMSTATE_STRUCT_VARRAY_UINT32(entries, InlineArrayState, count),
        VMSTATE_UINT32(count, InlineArrayState),
        VMSTATE_END_OF_LIST(),
    },
};

static const VMStateDescription unrelated_count = {
    .name = "unrelated-count",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]){
        VMSTATE_UINT32(unrelated, InlineArrayState),
        VMSTATE_STRUCT_VARRAY_UINT32(entries, InlineArrayState, count),
        VMSTATE_END_OF_LIST(),
    },
};

static const VMStateDescription conditional_count_is_unsupported = {
    .name = "conditional-count",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]){
        VMSTATE_UINT32_TEST(count, InlineArrayState, optional_field),
        VMSTATE_STRUCT_VARRAY_UINT32(entries, InlineArrayState, count),
        VMSTATE_END_OF_LIST(),
    },
};

static const VMStateDescription conditional_array_is_unsupported = {
    .name = "conditional-array",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]){
        VMSTATE_UINT32(count, InlineArrayState),
        VMSTATE_STRUCT_VARRAY_UINT32_TEST(entries, InlineArrayState, count,
                                          optional_field),
        VMSTATE_END_OF_LIST(),
    },
};

static const VMStateDescription unreachable_count_is_not_loaded = {
    .name = "unreachable-count",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]){
        VMSTATE_UINT32_V(count, InlineArrayState, 2), // expected-warning {{migration field requires version 2, but containing VMStateDescription 'unreachable_count_is_not_loaded' only writes version 1; this field can never be present}}
        VMSTATE_STRUCT_VARRAY_UINT32(entries, InlineArrayState, count),
        VMSTATE_END_OF_LIST(),
    },
};

static const VMStateDescription unreachable_array_is_not_loaded = {
    .name = "unreachable-array",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]){
        VMSTATE_UINT32(count, InlineArrayState),
        VMSTATE_STRUCT_VARRAY_UINT32_V(entries, InlineArrayState, count, 2), // expected-warning {{migration field requires version 2, but containing VMStateDescription 'unreachable_array_is_not_loaded' only writes version 1; this field can never be present}}
        VMSTATE_END_OF_LIST(),
    },
};

typedef struct PointerArrayState {
  unsigned count;
  unsigned *entries;
} PointerArrayState;

static const VMStateDescription allocated_pointer_array = {
    .name = "allocated-pointer-array",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]){
        VMSTATE_UINT32(count, PointerArrayState),
        VMSTATE_STRUCT_VARRAY_POINTER_UINT32(entries, PointerArrayState,
                                             count),
        VMSTATE_END_OF_LIST(),
    },
};

typedef struct ByteCountCapacity255State {
  unsigned char count;
  unsigned entries[255];
} ByteCountCapacity255State;

static const VMStateDescription byte_count_exactly_fits_capacity = {
    .name = "byte-count-capacity-255",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]){
        VMSTATE_UINT8(count, ByteCountCapacity255State),
        VMSTATE_STRUCT_VARRAY_UINT32(entries, ByteCountCapacity255State,
                                     count),
        VMSTATE_END_OF_LIST(),
    },
};

typedef struct ByteCountCapacity254State {
  unsigned char count;
  unsigned entries[254];
} ByteCountCapacity254State;

static const VMStateDescription byte_count_can_exceed_capacity = {
    .name = "byte-count-capacity-254",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]){
        VMSTATE_UINT8(count, ByteCountCapacity254State),
        VMSTATE_STRUCT_VARRAY_UINT32(entries, ByteCountCapacity254State, // inline-warning {{qemu.migration-inline-varray-count}}
                                     count),
        VMSTATE_END_OF_LIST(),
    },
};

typedef struct UnrelatedDescription {
  int version_id;
  int minimum_version_id;
} UnrelatedDescription;

static const UnrelatedDescription unrelated = {
    .version_id = 1,
    .minimum_version_id = 2,
};
