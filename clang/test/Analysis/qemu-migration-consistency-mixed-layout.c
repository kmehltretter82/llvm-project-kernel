// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.MigrationConsistency \
// RUN:   -analyzer-config alpha.qemu.MigrationConsistency:EnableInlineVArrayDiagnostics=true \
// RUN:   -verify %s
// expected-no-diagnostics

typedef __SIZE_TYPE__ size_t;
typedef unsigned int uint32_t;

typedef struct VMStateInfo VMStateInfo;
typedef struct VMStateDescription VMStateDescription;

struct VMStateInfo {
  const char *name;
};

typedef struct {
  size_t offset;
  size_t size;
} VMStateFieldReference;

/*
 * No released VMStateField has both count layouts.  Treat a mixed shape as
 * unsupported instead of interpreting the overlapping flag values.
 */
typedef struct {
  const char *name;
  size_t offset;
  size_t size;
  int num;
  size_t num_offset;
  VMStateFieldReference num_indirect;
  const VMStateInfo *info;
  unsigned flags;
  int version_id;
  _Bool (*field_exists)(void *, int);
} VMStateField;

struct VMStateDescription {
  const char *name;
  int version_id;
  int minimum_version_id;
  const VMStateField *fields;
};

static const VMStateInfo vmstate_info_uint32;

typedef struct MixedState {
  uint32_t count;
  uint32_t entries[2];
} MixedState;

static const VMStateDescription mixed_layout = {
    .name = "mixed-layout",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]){
        {
            .name = "count",
            .offset = __builtin_offsetof(MixedState, count),
            .size = sizeof(uint32_t),
            .info = &vmstate_info_uint32,
            .flags = 0x001,
        },
        {
            .name = "entries",
            .offset = __builtin_offsetof(MixedState, entries),
            .size = sizeof(uint32_t),
            .num_offset = __builtin_offsetof(MixedState, count),
            .num_indirect = {
                .offset = __builtin_offsetof(MixedState, count),
                .size = sizeof(uint32_t),
            },
            .flags = 0x010,
        },
        {},
    },
};
