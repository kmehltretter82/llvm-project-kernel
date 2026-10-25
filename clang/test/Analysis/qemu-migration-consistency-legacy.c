// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.MigrationConsistency \
// RUN:   -verify=noinline %s
// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.MigrationConsistency \
// RUN:   -analyzer-config alpha.qemu.MigrationConsistency:EnableInlineVArrayDiagnostics=true \
// RUN:   -verify=inline %s
// RUN: %clang_analyze_cc1 -triple i386-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.MigrationConsistency \
// RUN:   -verify=noinline %s
// RUN: %clang_analyze_cc1 -triple i386-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.MigrationConsistency \
// RUN:   -analyzer-config alpha.qemu.MigrationConsistency:EnableInlineVArrayDiagnostics=true \
// RUN:   -verify=inline %s

// noinline-no-diagnostics

typedef __SIZE_TYPE__ size_t;
typedef _Bool bool;
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef signed int int32_t;

#define typeof_field(_state, _field) __typeof__(((_state *)0)->_field)
#define type_check(_expected, _actual) \
  ((_expected *)0 - (_actual *)0)
#define vmstate_offset_value(_state, _field, _type)                  \
  (__builtin_offsetof(_state, _field) +                              \
   type_check(_type, typeof_field(_state, _field)))

typedef struct VMStateInfo VMStateInfo;
typedef struct VMStateDescription VMStateDescription;

struct VMStateInfo {
  const char *name;
};

enum VMStateFlags {
  VMS_SINGLE = 0x001,
  VMS_POINTER = 0x002,
  VMS_ARRAY = 0x004,
  VMS_STRUCT = 0x008,
  VMS_VARRAY_INT32 = 0x010,
  VMS_VARRAY_UINT16 = 0x080,
  VMS_VARRAY_UINT8 = 0x400,
  VMS_VARRAY_UINT32 = 0x800,
  VMS_MUST_EXIST = 0x1000,
};

/* This is the VMStateField layout used by the 2014 HPET fix. */
typedef struct {
  const char *name;
  size_t offset;
  size_t size;
  size_t start;
  int num;
  size_t num_offset;
  size_t size_offset;
  const VMStateInfo *info;
  enum VMStateFlags flags;
  const VMStateDescription *vmsd;
  int version_id;
  bool (*field_exists)(void *, int);
} VMStateField;

struct VMStateDescription {
  const char *name;
  int version_id;
  int minimum_version_id;
  const VMStateField *fields;
};

static const VMStateInfo vmstate_info_uint8;
static const VMStateInfo vmstate_info_uint16;
static const VMStateInfo vmstate_info_int32;
static const VMStateInfo vmstate_info_uint32;
static const VMStateInfo vmstate_info_uint32_equal;

#define VMSTATE_END_OF_LIST() {}
#define VMSTATE_SINGLE(_field, _state, _version, _info, _type)             \
  {                                                                        \
    .name = #_field, .version_id = (_version), .size = sizeof(_type),      \
    .info = &(_info), .flags = VMS_SINGLE,                                 \
    .offset = vmstate_offset_value(_state, _field, _type)                  \
  }
#define VMSTATE_UINT8_V(_field, _state, _version)                          \
  VMSTATE_SINGLE(_field, _state, _version, vmstate_info_uint8, uint8_t)
#define VMSTATE_UINT8(_field, _state)                                      \
  VMSTATE_UINT8_V(_field, _state, 0)
#define VMSTATE_UINT16(_field, _state)                                     \
  VMSTATE_SINGLE(_field, _state, 0, vmstate_info_uint16, uint16_t)
#define VMSTATE_INT32(_field, _state)                                      \
  VMSTATE_SINGLE(_field, _state, 0, vmstate_info_int32, int32_t)
#define VMSTATE_UINT32(_field, _state)                                     \
  VMSTATE_SINGLE(_field, _state, 0, vmstate_info_uint32, uint32_t)
#define VMSTATE_UINT32_EQUAL(_field, _state)                               \
  VMSTATE_SINGLE(_field, _state, 0, vmstate_info_uint32_equal, uint32_t)

#define VMSTATE_VALIDATE(_name, _test)                                     \
  {                                                                        \
    .name = (_name), .field_exists = (_test),                              \
    .flags = VMS_ARRAY | VMS_MUST_EXIST, .num = 0                          \
  }

#define LEGACY_STRUCT_VARRAY(_field, _state, _count, _version, _kind)      \
  {                                                                        \
    .name = #_field,                                                       \
    .num_offset = vmstate_offset_value(_state, _count,                     \
                                        typeof_field(_state, _count)),     \
    .version_id = (_version), .size = sizeof(((_state *)0)->_field[0]),    \
    .flags = VMS_STRUCT | (_kind),                                         \
    .offset = __builtin_offsetof(_state, _field)                            \
  }
#define VMSTATE_STRUCT_VARRAY_UINT8(_field, _state, _count, _version)      \
  LEGACY_STRUCT_VARRAY(_field, _state, _count, _version, VMS_VARRAY_UINT8)
#define VMSTATE_STRUCT_VARRAY_UINT16(_field, _state, _count, _version)     \
  LEGACY_STRUCT_VARRAY(_field, _state, _count, _version,                   \
                       VMS_VARRAY_UINT16)
#define VMSTATE_STRUCT_VARRAY_INT32(_field, _state, _count, _version)      \
  LEGACY_STRUCT_VARRAY(_field, _state, _count, _version, VMS_VARRAY_INT32)
#define VMSTATE_STRUCT_VARRAY_UINT32(_field, _state, _count, _version)     \
  LEGACY_STRUCT_VARRAY(_field, _state, _count, _version,                   \
                       VMS_VARRAY_UINT32)
#define VMSTATE_STRUCT_VARRAY_POINTER_UINT32(_field, _state, _count)       \
  {                                                                        \
    .name = #_field,                                                       \
    .num_offset = vmstate_offset_value(_state, _count, uint32_t),          \
    .size = sizeof(((_state *)0)->_field[0]),                              \
    .flags = VMS_POINTER | VMS_STRUCT | VMS_VARRAY_UINT32,                 \
    .offset = __builtin_offsetof(_state, _field)                            \
  }

typedef struct LegacyEntry {
  unsigned value;
} LegacyEntry;

typedef struct LegacyHpetState {
  uint8_t num_timers;
  uint8_t unrelated;
  LegacyEntry timer[32];
} LegacyHpetState;

static bool hpet_count_is_valid(void *opaque, int version_id) {
  LegacyHpetState *state = opaque;
  return state->num_timers >= 3 && state->num_timers <= 32;
}

static bool unrelated_is_valid(void *opaque, int version_id) {
  LegacyHpetState *state = opaque;
  return state->unrelated <= 1;
}

static bool count_is_nonzero(void *opaque, int version_id) {
  LegacyHpetState *state = opaque;
  return state->num_timers != 0;
}

static const VMStateDescription historical_hpet_parent = {
    .name = "historical-hpet-parent",
    .version_id = 2,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]){
        VMSTATE_UINT8_V(num_timers, LegacyHpetState, 2),
        VMSTATE_STRUCT_VARRAY_UINT8(timer, LegacyHpetState, num_timers, 0), // inline-warning {{qemu.migration-inline-varray-count}}
        VMSTATE_END_OF_LIST(),
    },
};

static const VMStateDescription historical_hpet_fix = {
    .name = "historical-hpet-fix",
    .version_id = 2,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]){
        VMSTATE_UINT8_V(num_timers, LegacyHpetState, 2),
        VMSTATE_VALIDATE("num_timers in range", hpet_count_is_valid),
        VMSTATE_STRUCT_VARRAY_UINT8(timer, LegacyHpetState, num_timers, 0),
        VMSTATE_END_OF_LIST(),
    },
};

static const VMStateDescription legacy_late_validation = {
    .name = "legacy-late-validation",
    .version_id = 2,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]){
        VMSTATE_UINT8_V(num_timers, LegacyHpetState, 2),
        VMSTATE_STRUCT_VARRAY_UINT8(timer, LegacyHpetState, num_timers, 0), // inline-warning {{qemu.migration-inline-varray-count}}
        VMSTATE_VALIDATE("num_timers in range", hpet_count_is_valid),
        VMSTATE_END_OF_LIST(),
    },
};

static const VMStateDescription legacy_unrelated_validation = {
    .name = "legacy-unrelated-validation",
    .version_id = 2,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]){
        VMSTATE_UINT8_V(num_timers, LegacyHpetState, 2),
        VMSTATE_VALIDATE("unrelated in range", unrelated_is_valid),
        VMSTATE_STRUCT_VARRAY_UINT8(timer, LegacyHpetState, num_timers, 0), // inline-warning {{qemu.migration-inline-varray-count}}
        VMSTATE_END_OF_LIST(),
    },
};

/*
 * A predicate that merely mentions the count is not an upper-bound proof.
 * The first D9 slice deliberately retires precision at such a validator, so
 * this remains a no-warning case rather than a semantic-validation claim.
 */
static const VMStateDescription legacy_ineffective_count_validation = {
    .name = "legacy-ineffective-count-validation",
    .version_id = 2,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]){
        VMSTATE_UINT8_V(num_timers, LegacyHpetState, 2),
        VMSTATE_VALIDATE("num_timers is nonzero", count_is_nonzero),
        VMSTATE_STRUCT_VARRAY_UINT8(timer, LegacyHpetState, num_timers, 0),
        VMSTATE_END_OF_LIST(),
    },
};

static const VMStateDescription legacy_ambiguous_varray_kind = {
    .name = "legacy-ambiguous-varray-kind",
    .version_id = 2,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]){
        VMSTATE_UINT8_V(num_timers, LegacyHpetState, 2),
        {
            .name = "timer",
            .num_offset = vmstate_offset_value(LegacyHpetState, num_timers,
                                                uint8_t),
            .size = sizeof(LegacyEntry),
            .flags = VMS_STRUCT | VMS_VARRAY_UINT8 | VMS_VARRAY_UINT16,
            .offset = __builtin_offsetof(LegacyHpetState, timer),
        },
        VMSTATE_END_OF_LIST(),
    },
};

typedef struct LegacyByteCapacity255 {
  uint8_t count;
  LegacyEntry entries[255];
} LegacyByteCapacity255;

static const VMStateDescription legacy_byte_capacity_255 = {
    .name = "legacy-byte-capacity-255",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]){
        VMSTATE_UINT8(count, LegacyByteCapacity255),
        VMSTATE_STRUCT_VARRAY_UINT8(entries, LegacyByteCapacity255, count, 0),
        VMSTATE_END_OF_LIST(),
    },
};

typedef struct LegacyByteCapacity254 {
  uint8_t count;
  LegacyEntry entries[254];
} LegacyByteCapacity254;

static const VMStateDescription legacy_byte_capacity_254 = {
    .name = "legacy-byte-capacity-254",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]){
        VMSTATE_UINT8(count, LegacyByteCapacity254),
        VMSTATE_STRUCT_VARRAY_UINT8(entries, LegacyByteCapacity254, count, 0), // inline-warning {{qemu.migration-inline-varray-count}}
        VMSTATE_END_OF_LIST(),
    },
};

typedef struct LegacyWideCounts {
  int32_t signed_count;
  uint16_t short_count;
  uint32_t wide_count;
  LegacyEntry signed_entries[64];
  LegacyEntry short_entries[64];
  LegacyEntry wide_entries[64];
} LegacyWideCounts;

static const VMStateDescription legacy_typed_varrays = {
    .name = "legacy-typed-varrays",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]){
        VMSTATE_INT32(signed_count, LegacyWideCounts),
        VMSTATE_STRUCT_VARRAY_INT32(signed_entries, LegacyWideCounts, // inline-warning {{qemu.migration-inline-varray-count}}
                                    signed_count, 0),
        VMSTATE_UINT16(short_count, LegacyWideCounts),
        VMSTATE_STRUCT_VARRAY_UINT16(short_entries, LegacyWideCounts, // inline-warning {{qemu.migration-inline-varray-count}}
                                     short_count, 0),
        VMSTATE_UINT32(wide_count, LegacyWideCounts),
        VMSTATE_STRUCT_VARRAY_UINT32(wide_entries, LegacyWideCounts, // inline-warning {{qemu.migration-inline-varray-count}}
                                     wide_count, 0),
        VMSTATE_END_OF_LIST(),
    },
};

typedef struct LegacyPointerArray {
  uint32_t count;
  LegacyEntry *entries;
} LegacyPointerArray;

static const VMStateDescription legacy_pointer_array = {
    .name = "legacy-pointer-array",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]){
        VMSTATE_UINT32(count, LegacyPointerArray),
        VMSTATE_STRUCT_VARRAY_POINTER_UINT32(entries, LegacyPointerArray,
                                             count),
        VMSTATE_END_OF_LIST(),
    },
};

typedef struct LegacyEqualCount {
  uint32_t count;
  LegacyEntry entries[4];
} LegacyEqualCount;

static const VMStateDescription legacy_equal_count = {
    .name = "legacy-equal-count",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]){
        VMSTATE_UINT32_EQUAL(count, LegacyEqualCount),
        VMSTATE_STRUCT_VARRAY_UINT32(entries, LegacyEqualCount, count, 0),
        VMSTATE_END_OF_LIST(),
    },
};
