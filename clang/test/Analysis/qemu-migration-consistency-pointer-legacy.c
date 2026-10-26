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

// noopt-no-diagnostics

typedef __SIZE_TYPE__ size_t;
typedef _Bool bool;
typedef unsigned short uint16_t;

typedef struct QEMUFile QEMUFile;
typedef struct VMStateIf VMStateIf;
typedef struct VMStateDescription VMStateDescription;

typedef struct VMStateInfo {
  const char *name;
  int (*get)(QEMUFile *, void *, size_t);
} VMStateInfo;

enum VMStateFlags {
  VMS_SINGLE = 0x001,
  VMS_POINTER = 0x002,
  VMS_ARRAY = 0x004,
  VMS_STRUCT = 0x008,
  VMS_VARRAY_UINT16 = 0x080,
  VMS_MUST_EXIST = 0x1000,
};

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
  int unmigratable;
  int version_id;
  int minimum_version_id;
  int minimum_version_id_old;
  void *load_state_old;
  int (*pre_load)(void *);
  int (*post_load)(void *, int);
  void (*pre_save)(void *);
  VMStateField *fields;
};

void *g_malloc0(size_t size);
int vmstate_register_any(VMStateIf *obj, const VMStateDescription *vmsd,
                         void *opaque);

static const VMStateInfo vmstate_info_uint16;
static const VMStateInfo vmstate_info_uint16_equal;

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
#define VMSTATE_VALIDATE(_name, _test)                                         \
  {                                                                            \
      .name = (_name),                                                         \
      .field_exists = (_test),                                                 \
      .flags = VMS_ARRAY | VMS_MUST_EXIST,                                     \
      .num = 0,                                                                \
  }
#define VMSTATE_STRUCT_VARRAY_POINTER_UINT16(_field, _state, _count)           \
  {                                                                            \
      .name = #_field,                                                         \
      .offset = __builtin_offsetof(_state, _field),                            \
      .size = sizeof(((_state *)0)->_field[0]),                                \
      .num_offset = __builtin_offsetof(_state, _count),                        \
      .flags = VMS_POINTER | VMS_STRUCT | VMS_VARRAY_UINT16,                   \
  }
#define VMSTATE_END_OF_LIST()                                                  \
  {                                                                            \
  }

typedef struct LegacyState {
  uint16_t count;
  uint16_t capacity;
  unsigned *entries;
} LegacyState;

static void legacy_allocate(LegacyState *state) {
  state->entries = g_malloc0(sizeof state->entries[0] * state->capacity);
}

static bool legacy_count_valid(void *opaque, int version_id) {
  LegacyState *state = opaque;
  return state->count <= state->capacity;
}

static const VMStateDescription legacy_parent = {
    .name = "legacy-parent",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields =
        (VMStateField[]){
            VMSTATE_UINT16(count, LegacyState),
            VMSTATE_UINT16(capacity, LegacyState),
            VMSTATE_STRUCT_VARRAY_POINTER_UINT16( // pointer-warning {{qemu.migration-pointer-varray-capacity}}
                entries, LegacyState,
                count),
            VMSTATE_END_OF_LIST(),
        },
};

static const VMStateDescription legacy_fix = {
    .name = "legacy-fix",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields =
        (VMStateField[]){
            VMSTATE_UINT16(count, LegacyState),
            VMSTATE_UINT16_EQUAL(capacity, LegacyState),
            VMSTATE_VALIDATE("count <= capacity", legacy_count_valid),
            VMSTATE_STRUCT_VARRAY_POINTER_UINT16(entries, LegacyState, count),
            VMSTATE_END_OF_LIST(),
        },
};

static void register_legacy(VMStateIf *obj, void *opaque) {
  vmstate_register_any(obj, &legacy_parent, opaque);
  vmstate_register_any(obj, &legacy_fix, opaque);
}
