// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.qemu.MigrationConsistency -verify %s

typedef __SIZE_TYPE__ size_t;
typedef _Bool bool;

typedef struct VMStateField {
  const char *name;
  size_t size;
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

typedef struct UnrelatedDescription {
  int version_id;
  int minimum_version_id;
} UnrelatedDescription;

static const UnrelatedDescription unrelated = {
    .version_id = 1,
    .minimum_version_id = 2,
};
