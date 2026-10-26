// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.MigrationConsistency \
// RUN:   -verify=noopt %s
// RUN: %clang_analyze_cc1 -triple i386-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.MigrationConsistency \
// RUN:   -verify=noopt %s
// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.MigrationConsistency \
// RUN:   -analyzer-config \
// RUN:   alpha.qemu.MigrationConsistency:EnablePointerVArrayDiagnostics=true \
// RUN:   -verify=pointer %s
// RUN: %clang_analyze_cc1 -triple i386-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.MigrationConsistency \
// RUN:   -analyzer-config \
// RUN:   alpha.qemu.MigrationConsistency:EnablePointerVArrayDiagnostics=true \
// RUN:   -verify=pointer %s
// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.MigrationConsistency \
// RUN:   -analyzer-config \
// RUN:   alpha.qemu.MigrationConsistency:EnablePointerVArrayDiagnostics=true \
// RUN:   -analyzer-config \
// RUN:   alpha.qemu.MigrationConsistency:ReachablePointerVArrayDescriptions=external_reachable \
// RUN:   -verify=pointer,external %s

// noopt-no-diagnostics

typedef __SIZE_TYPE__ size_t;
typedef _Bool bool;
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;

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
  VMS_ARRAY_OF_POINTER = 0x040,
  VMS_NO_STATE = 0x080,
  VMS_MUST_EXIST = 0x1000,
  VMS_ALLOC = 0x2000,
  VMS_ARRAY_OF_POINTER_AUTO_ALLOC = 0x10000,
  VMS_END = 0x20000,
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

void *g_malloc0(size_t size);
void *g_malloc_n(size_t count, size_t size);
void *g_malloc0_n(size_t count, size_t size);
int vmstate_register_any(VMStateIf *obj, const VMStateDescription *vmsd,
                         void *opaque);

static const VMStateInfo vmstate_info_uint16;
static const VMStateInfo vmstate_info_uint16_equal;

#define vmstate_field_offset(_state, _field)                                   \
  {                                                                            \
      .offset = __builtin_offsetof(_state, _field),                            \
      .size = sizeof(((_state *)0)->_field),                                   \
  }
#define VMSTATE_UINT16(_field, _state)                                         \
  {                                                                            \
      .name = #_field,                                                         \
      .offset = __builtin_offsetof(_state, _field),                            \
      .size = sizeof(uint16_t),                                                \
      .info = &vmstate_info_uint16,                                            \
      .flags = VMS_SINGLE,                                                     \
  }
#define VMSTATE_UINT16_EQUAL(_field, _state)                                   \
  {                                                                            \
      .name = #_field,                                                         \
      .offset = __builtin_offsetof(_state, _field),                            \
      .size = sizeof(uint16_t),                                                \
      .info = &vmstate_info_uint16_equal,                                      \
      .flags = VMS_SINGLE,                                                     \
  }
#define VMSTATE_POINTER_VARRAY(_field, _state, _count)                         \
  {                                                                            \
      .name = #_field,                                                         \
      .offset = __builtin_offsetof(_state, _field),                            \
      .size = sizeof(((_state *)0)->_field[0]),                                \
      .num_indirect = vmstate_field_offset(_state, _count),                    \
      .flags = VMS_POINTER | VMS_VARRAY | VMS_STRUCT,                          \
  }
#define VMSTATE_POINTER_VARRAY_ALLOC(_field, _state, _count)                   \
  {                                                                            \
      .name = #_field,                                                         \
      .offset = __builtin_offsetof(_state, _field),                            \
      .size = sizeof(((_state *)0)->_field[0]),                                \
      .num_indirect = vmstate_field_offset(_state, _count),                    \
      .flags = VMS_POINTER | VMS_VARRAY | VMS_STRUCT | VMS_ALLOC,              \
  }
#define VMSTATE_POINTER_ELEMENT_AUTO_ALLOC(_field, _state, _count, _type)      \
  {                                                                            \
      .name = #_field,                                                         \
      .offset = __builtin_offsetof(_state, _field),                            \
      .size = sizeof(_type),                                                   \
      .num_indirect = vmstate_field_offset(_state, _count),                    \
      .flags = VMS_POINTER | VMS_VARRAY | VMS_STRUCT | VMS_ARRAY_OF_POINTER |  \
               VMS_ARRAY_OF_POINTER_AUTO_ALLOC,                                \
  }
#define VMSTATE_VALIDATE(_test)                                                \
  {                                                                            \
      .name = "validate",                                                      \
      .field_exists = (_test),                                                 \
      .flags = VMS_MUST_EXIST | VMS_NO_STATE,                                  \
  }
#define VMSTATE_EMBED(_description)                                            \
  {                                                                            \
      .name = #_description,                                                   \
      .vmsd = &(_description),                                                 \
      .flags = VMS_STRUCT,                                                     \
  }
#define VMSTATE_END_OF_LIST()                                                  \
  {                                                                            \
      .flags = VMS_END,                                                        \
  }

typedef struct PointerState {
  uint16_t count;
  uint16_t capacity;
  uint16_t other_count;
  uint16_t other_capacity;
  unsigned *entries;
} PointerState;

static void pointer_state_allocate(PointerState *state) {
  state->entries = g_malloc0(sizeof state->entries[0] * state->capacity);
}

static bool count_fits_capacity(void *opaque, int version_id) {
  PointerState *state = opaque;
  return state->count <= state->capacity;
}

static bool other_count_fits_other_capacity(void *opaque, int version_id) {
  PointerState *state = opaque;
  return state->other_count <= state->other_capacity;
}

static const VMStateDescription cve_parent = {
    .name = "cve-parent",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields =
        (const VMStateField[]){
            VMSTATE_UINT16(count, PointerState),
            VMSTATE_UINT16(capacity, PointerState),
            VMSTATE_POINTER_VARRAY( // pointer-warning {{qemu.migration-pointer-varray-capacity}}
                entries, PointerState,
                count),
            VMSTATE_END_OF_LIST(),
        },
};

static const VMStateDescription cve_fix = {
    .name = "cve-fix",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields =
        (const VMStateField[]){
            VMSTATE_UINT16(count, PointerState),
            VMSTATE_UINT16_EQUAL(capacity, PointerState),
            VMSTATE_VALIDATE(count_fits_capacity),
            VMSTATE_POINTER_VARRAY(entries, PointerState, count),
            VMSTATE_END_OF_LIST(),
        },
};

static const VMStateDescription equality_only = {
    .name = "equality-only",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields =
        (const VMStateField[]){
            VMSTATE_UINT16(count, PointerState),
            VMSTATE_UINT16_EQUAL(capacity, PointerState),
            VMSTATE_POINTER_VARRAY( // pointer-warning {{qemu.migration-pointer-varray-capacity}}
                entries, PointerState,
                count),
            VMSTATE_END_OF_LIST(),
        },
};

static const VMStateDescription validator_only = {
    .name = "validator-only",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields =
        (const VMStateField[]){
            VMSTATE_UINT16(count, PointerState),
            VMSTATE_UINT16(capacity, PointerState),
            VMSTATE_VALIDATE(count_fits_capacity),
            VMSTATE_POINTER_VARRAY( // pointer-warning {{qemu.migration-pointer-varray-capacity}}
                entries, PointerState,
                count),
            VMSTATE_END_OF_LIST(),
        },
};

static const VMStateDescription validator_after_varray = {
    .name = "validator-after-varray",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields =
        (const VMStateField[]){
            VMSTATE_UINT16(count, PointerState),
            VMSTATE_UINT16_EQUAL(capacity, PointerState),
            VMSTATE_POINTER_VARRAY( // pointer-warning {{qemu.migration-pointer-varray-capacity}}
                entries, PointerState,
                count),
            VMSTATE_VALIDATE(count_fits_capacity),
            VMSTATE_END_OF_LIST(),
        },
};

static const VMStateDescription wrong_fields = {
    .name = "wrong-fields",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields =
        (const VMStateField[]){
            VMSTATE_UINT16(count, PointerState),
            VMSTATE_UINT16_EQUAL(other_capacity, PointerState),
            VMSTATE_VALIDATE(other_count_fits_other_capacity),
            VMSTATE_POINTER_VARRAY( // pointer-warning {{qemu.migration-pointer-varray-capacity}}
                entries, PointerState,
                count),
            VMSTATE_END_OF_LIST(),
        },
};

typedef struct SameCountCapacityState {
  uint16_t count;
  unsigned *entries;
} SameCountCapacityState;

static void same_count_capacity_allocate(SameCountCapacityState *state) {
  state->entries = g_malloc0(sizeof state->entries[0] * state->count);
}

static const VMStateDescription loaded_allocation_count = {
    .name = "loaded-allocation-count",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields =
        (const VMStateField[]){
            VMSTATE_UINT16(count, SameCountCapacityState),
            VMSTATE_POINTER_VARRAY( // pointer-warning {{qemu.migration-pointer-varray-capacity}}
                entries, SameCountCapacityState,
                count),
            VMSTATE_END_OF_LIST(),
        },
};

static const VMStateDescription vms_alloc_is_outer_allocation = {
    .name = "vms-alloc",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields =
        (const VMStateField[]){
            VMSTATE_UINT16(count, PointerState),
            VMSTATE_POINTER_VARRAY_ALLOC(entries, PointerState, count),
            VMSTATE_END_OF_LIST(),
        },
};

typedef struct AutoOuterState {
  uint16_t count;
  unsigned *entries;
} AutoOuterState;

static const VMStateDescription auto_allocated_outer_array = {
    .name = "auto-allocated-outer-array",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields =
        (const VMStateField[]){
            VMSTATE_UINT16(count, AutoOuterState),
            VMSTATE_POINTER_VARRAY_ALLOC(entries, AutoOuterState, count),
            VMSTATE_END_OF_LIST(),
        },
};

typedef struct Element {
  unsigned value;
} Element;

typedef struct AutoElementState {
  uint16_t count;
  uint16_t capacity;
  Element **entries;
} AutoElementState;

static void auto_element_state_allocate(AutoElementState *state) {
  state->entries = g_malloc0(sizeof state->entries[0] * state->capacity);
}

static const VMStateDescription auto_allocated_elements_only = {
    .name = "auto-allocated-elements-only",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields =
        (const VMStateField[]){
            VMSTATE_UINT16(count, AutoElementState),
            VMSTATE_POINTER_ELEMENT_AUTO_ALLOC( // pointer-warning {{qemu.migration-pointer-varray-capacity}}
                entries, AutoElementState, count,
                Element),
            VMSTATE_END_OF_LIST(),
        },
};

typedef struct ArrayAllocatorState {
  uint16_t count;
  uint16_t capacity;
  unsigned *zeroed_entries;
  unsigned *plain_entries;
} ArrayAllocatorState;

static void array_allocator_state_allocate(ArrayAllocatorState *state) {
  state->zeroed_entries =
      (unsigned *)g_malloc0_n(state->capacity, sizeof(unsigned));
  state->plain_entries =
      (unsigned *)g_malloc_n(sizeof(unsigned), state->capacity);
}

static const VMStateDescription g_malloc0_n_capacity = {
    .name = "g-malloc0-n-capacity",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields =
        (const VMStateField[]){
            VMSTATE_UINT16(count, ArrayAllocatorState),
            VMSTATE_POINTER_VARRAY( // pointer-warning {{qemu.migration-pointer-varray-capacity}}
                zeroed_entries, ArrayAllocatorState,
                count),
            VMSTATE_END_OF_LIST(),
        },
};

static const VMStateDescription g_malloc_n_capacity = {
    .name = "g-malloc-n-capacity",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields =
        (const VMStateField[]){
            VMSTATE_UINT16(count, ArrayAllocatorState),
            VMSTATE_POINTER_VARRAY( // pointer-warning {{qemu.migration-pointer-varray-capacity}}
                plain_entries, ArrayAllocatorState,
                count),
            VMSTATE_END_OF_LIST(),
        },
};

typedef struct WrongAllocationState {
  uint16_t count;
  uint16_t capacity;
  unsigned *entries;
  unsigned *other_entries;
} WrongAllocationState;

static void wrong_allocation_relation(WrongAllocationState *state) {
  state->entries = g_malloc0(sizeof state->other_entries[0] * state->capacity);
}

static const VMStateDescription uncertain_allocation_is_unsupported = {
    .name = "uncertain-allocation",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields =
        (const VMStateField[]){
            VMSTATE_UINT16(count, WrongAllocationState),
            VMSTATE_POINTER_VARRAY(entries, WrongAllocationState, count),
            VMSTATE_END_OF_LIST(),
        },
};

extern bool opaque_bound_helper(uint16_t count, uint16_t capacity);

static bool opaque_validator(void *opaque, int version_id) {
  PointerState *state = opaque;
  return opaque_bound_helper(state->count, state->capacity);
}

static const VMStateDescription opaque_validator_is_unsupported = {
    .name = "opaque-validator",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields =
        (const VMStateField[]){
            VMSTATE_UINT16(count, PointerState),
            VMSTATE_VALIDATE(opaque_validator),
            VMSTATE_POINTER_VARRAY(entries, PointerState, count),
            VMSTATE_END_OF_LIST(),
        },
};

static int pointer_pre_load(void *opaque) { return 0; }

static const VMStateDescription pre_load_is_unsupported = {
    .name = "pre-load",
    .version_id = 1,
    .minimum_version_id = 1,
    .pre_load = pointer_pre_load,
    .fields =
        (const VMStateField[]){
            VMSTATE_UINT16(count, PointerState),
            VMSTATE_POINTER_VARRAY(entries, PointerState, count),
            VMSTATE_END_OF_LIST(),
        },
};

typedef struct AmbiguousAllocationState {
  uint16_t count;
  uint16_t capacity;
  unsigned *entries;
} AmbiguousAllocationState;

static void ambiguous_allocate_one(AmbiguousAllocationState *state) {
  state->entries = g_malloc0(sizeof state->entries[0] * state->capacity);
}

static void ambiguous_allocate_two(AmbiguousAllocationState *state) {
  state->entries = g_malloc0(sizeof state->entries[0] * state->capacity);
}

static const VMStateDescription ambiguous_allocation_is_unsupported = {
    .name = "ambiguous-allocation",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields =
        (const VMStateField[]){
            VMSTATE_UINT16(count, AmbiguousAllocationState),
            VMSTATE_POINTER_VARRAY(entries, AmbiguousAllocationState, count),
            VMSTATE_END_OF_LIST(),
        },
};

static const VMStateDescription unreachable_descriptor = {
    .name = "unreachable-descriptor",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields =
        (const VMStateField[]){
            VMSTATE_UINT16(count, PointerState),
            VMSTATE_POINTER_VARRAY(entries, PointerState, count),
            VMSTATE_END_OF_LIST(),
        },
};

static const VMStateDescription external_reachable = {
    .name = "external-reachable",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields =
        (const VMStateField[]){
            VMSTATE_UINT16(count, PointerState),
            VMSTATE_POINTER_VARRAY( // external-warning {{qemu.migration-pointer-varray-capacity}}
                entries, PointerState,
                count),
            VMSTATE_END_OF_LIST(),
        },
};

static const VMStateField root_fields[] = {
    VMSTATE_EMBED(cve_fix),
    VMSTATE_EMBED(equality_only),
    VMSTATE_EMBED(validator_only),
    VMSTATE_EMBED(validator_after_varray),
    VMSTATE_EMBED(wrong_fields),
    VMSTATE_EMBED(loaded_allocation_count),
    VMSTATE_EMBED(vms_alloc_is_outer_allocation),
    VMSTATE_EMBED(auto_allocated_outer_array),
    VMSTATE_EMBED(auto_allocated_elements_only),
    VMSTATE_EMBED(g_malloc0_n_capacity),
    VMSTATE_EMBED(g_malloc_n_capacity),
    VMSTATE_EMBED(uncertain_allocation_is_unsupported),
    VMSTATE_EMBED(opaque_validator_is_unsupported),
    VMSTATE_EMBED(pre_load_is_unsupported),
    VMSTATE_EMBED(ambiguous_allocation_is_unsupported),
    VMSTATE_END_OF_LIST(),
};

static const VMStateDescription root = {
    .name = "root",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = root_fields,
};

static void register_root(VMStateIf *obj, void *opaque) {
  vmstate_register_any(obj, &cve_parent, opaque);
  vmstate_register_any(obj, &root, opaque);
}
