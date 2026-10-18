// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.qemu.GuestMemorySafety -analyzer-output=text -verify %s

typedef __SIZE_TYPE__ size_t;
typedef __UINT64_TYPE__ uint64_t;

typedef struct BdrvChild BdrvChild;
typedef struct NetClientState NetClientState;
typedef struct VirtIODevice VirtIODevice;
typedef struct QEMUIOVector QEMUIOVector;

struct VirtIODevice {
  size_t config_len;
};

void *memcpy(void *, const void *, size_t);
void *memmove(void *, const void *, size_t);
void *memset(void *, int, size_t);
void *malloc(size_t);
unsigned dma_memory_read(void *, uint64_t, void *, size_t, unsigned);
void physical_memory_read(uint64_t, void *, uint64_t);
size_t qemu_get_buffer(void *, unsigned char *, size_t);
int bdrv_pread(BdrvChild *, long long, long long, void *, unsigned);
unsigned qemu_get_byte(void *);
size_t qemu_iovec_to_buf(QEMUIOVector *, size_t, void *, size_t);
int range_covers_byte(uint64_t, uint64_t, uint64_t);
long qemu_send_packet(void *, const unsigned char *, int);
int test_bit(long, const unsigned long *);
void set_bit(long, unsigned long *);
void clear_bit(long, unsigned long *);

typedef struct MemoryRegionOps {
  uint64_t (*read)(void *, uint64_t, unsigned);
  void (*write)(void *, uint64_t, uint64_t, unsigned);
  int (*read_with_attrs)(void *, uint64_t, uint64_t *, unsigned, unsigned);
  int (*write_with_attrs)(void *, uint64_t, uint64_t, unsigned, unsigned);
  unsigned endianness;
  struct {
    unsigned min_access_size;
    unsigned max_access_size;
    _Bool unaligned;
    _Bool (*accepts)(void *, uint64_t, unsigned, _Bool, unsigned);
  } valid;
  struct {
    unsigned min_access_size;
    unsigned max_access_size;
    _Bool unaligned;
  } impl;
} MemoryRegionOps;

typedef struct MemoryRegionPortio {
  unsigned offset;
  unsigned len;
  unsigned size;
  unsigned (*read)(void *, unsigned);
  void (*write)(void *, unsigned, unsigned);
} MemoryRegionPortio;

typedef struct MemoryRegion {
  int opaque;
} MemoryRegion;

void memory_region_init_io(MemoryRegion *, void *, const MemoryRegionOps *,
                           void *, const char *, uint64_t);

typedef struct NetClientInfo {
  unsigned type;
  size_t size;
  long (*receive)(NetClientState *, const unsigned char *, size_t);
  long (*receive_iov)(void *, const void *, int);
} NetClientInfo;

typedef struct VirtioDeviceClass {
  void (*set_config)(VirtIODevice *, const unsigned char *);
} VirtioDeviceClass;

typedef struct VMStateField {
  size_t offset;
  unsigned flags;
  _Bool (*field_exists)(void *, int);
} VMStateField;

typedef struct VMStateDescription {
  int (*post_load)(void *, int);
  const VMStateField *fields;
} VMStateDescription;

enum {
  VMS_NO_STATE = 0x080,
  VMS_MUST_EXIST = 0x1000,
};

#define VMSTATE_UINT32(_field, _state)                                     \
  { .offset = __builtin_offsetof(_state, _field) }
#define VMSTATE_UINT8(_field, _state)                                      \
  { .offset = __builtin_offsetof(_state, _field) }
#define VMSTATE_UINT16(_field, _state)                                     \
  { .offset = __builtin_offsetof(_state, _field) }
#define VMSTATE_VALIDATE(_name, _test)                                     \
  { .flags = VMS_MUST_EXIST | VMS_NO_STATE, .field_exists = (_test) }
#define VMSTATE_END_OF_LIST()                                              \
  { .offset = (size_t)-1 }

static unsigned virtio_config_result;

static void virtio_config_index(VirtIODevice *device,
                                const unsigned char *config) {
  int slots[4] = {0};
  if (device->config_len < 2) // expected-note {{Assuming field 'config_len' is >= 2}}
                               // expected-note@-1 {{Taking false branch}}
    return;
  virtio_config_result = slots[config[1]]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                                            // expected-note@-1 {{virtio configuration callback parameter 'config' is guest-controlled}}
                                            // expected-note@-2 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static void register_virtio_config_callback(VirtioDeviceClass *vdc) {
  vdc->set_config = virtio_config_index;
}

static void mmio_copy(void *opaque, uint64_t addr, uint64_t data, // expected-note {{MMIO callback parameter 'size' is guest-controlled}}
                      unsigned size) {
  char destination[4];
  memcpy(destination, opaque, size); // expected-warning {{Level B: guest-controlled memory-operation length may exceed the host object extent}}
                                    // expected-note@-1 {{Level B: guest-controlled memory-operation length may exceed the host object extent}}
}

static void mmio_definite_copy(void *opaque, uint64_t addr, uint64_t data, // expected-note {{MMIO callback parameter 'size' is guest-controlled}}
                               unsigned size) {
  char destination[4];
  if (size <= sizeof(destination)) // expected-note {{Assuming the condition is false}}
                                   // expected-note@-1 {{Taking false branch}}
    return;
  memcpy(destination, opaque, size); // expected-warning {{Level A: guest-controlled memory-operation length exceeds the host object extent}}
                                    // expected-note@-1 {{Level A: guest-controlled memory-operation length exceeds the host object extent}}
}

static void mmio_bounded_copy(void *opaque, uint64_t addr, uint64_t data,
                              unsigned size) {
  char destination[8];
  if (size > sizeof(destination))
    return;
  memcpy(destination, opaque, size);
}

static void mmio_source_overread(void *opaque, uint64_t addr, uint64_t data,
                                 unsigned size) { // expected-note@-1 {{MMIO callback parameter 'size' is guest-controlled}}
  unsigned char source[4] = {0};
  unsigned char destination[16];
  if (size > sizeof(destination)) // expected-note {{Taking false branch}}
    return;
  memcpy(destination, source, size); // expected-warning {{Level B: guest-controlled memory-operation source length may exceed the host object extent}}
                                     // expected-note@-1 {{Level B: guest-controlled memory-operation source length may exceed the host object extent}}
}

static void mmio_packet_overread(void *opaque, uint64_t addr, uint64_t data, // expected-note {{MMIO callback parameter 'data' is guest-controlled}}
                                 unsigned size) {
  unsigned char packet[8] = {0};
  qemu_send_packet(opaque, packet, data); // expected-warning {{Level B: guest-controlled packet length may exceed the host object extent}}
                                          // expected-note@-1 {{Level B: guest-controlled packet length may exceed the host object extent}}
}

typedef struct PersistentPacketState {
  unsigned packet_length;
  unsigned char packet[8];
} PersistentPacketState;

static void mmio_persistent_packet_overread(void *opaque, uint64_t addr,
                                            uint64_t data, unsigned size) {
  PersistentPacketState *s = opaque;
  if (addr == 0) { // expected-note {{Assuming 'addr' is not equal to 0}}
                   // expected-note@-1 {{Taking false branch}}
    s->packet_length = data;
  } else if (addr == 4) { // expected-note {{Assuming 'addr' is equal to 4}}
                          // expected-note@-1 {{Taking true branch}}
    qemu_send_packet(opaque, s->packet, s->packet_length); // expected-warning {{Level B: guest-controlled packet length may exceed the host object extent}} expected-note {{MMIO stored field 'packet_length' is guest-controlled}}
                                                           // expected-note@-1 {{Level B: guest-controlled packet length may exceed the host object extent}}
  }
}

static void mmio_persistent_bounded_packet(void *opaque, uint64_t addr,
                                           uint64_t data, unsigned size) {
  PersistentPacketState *s = opaque;
  if (addr == 0) {
    s->packet_length = data;
  } else if (addr == 4) {
    if (s->packet_length > sizeof(s->packet))
      return;
    qemu_send_packet(opaque, s->packet, s->packet_length);
  }
}

static const MemoryRegionOps mmio_overread_ops = {
    .write = mmio_source_overread,
};

static const MemoryRegionOps mmio_packet_overread_ops = {
    .write = mmio_packet_overread,
};

static const MemoryRegionOps mmio_persistent_packet_ops = {
    .write = mmio_persistent_packet_overread,
};

static const MemoryRegionOps mmio_persistent_bounded_packet_ops = {
    .write = mmio_persistent_bounded_packet,
};

typedef struct PersistentChannelState {
  unsigned channel;
  int channels[2];
} PersistentChannelState;

static void mmio_persistent_clamped_channel(void *opaque, uint64_t addr,
                                            uint64_t data, unsigned size) {
  PersistentChannelState *s = opaque;
  if (addr == 0)
    s->channel = data < 2 ? data : 0;
  else if (addr == 4)
    s->channels[s->channel] = 1;
}

typedef struct PersistentOffByOneChannelState {
  unsigned channel;
  int channels[2];
} PersistentOffByOneChannelState;

static void mmio_persistent_off_by_one_channel(void *opaque, uint64_t addr,
                                               uint64_t data, unsigned size) {
  PersistentOffByOneChannelState *s = opaque;
  if (addr == 0) { // expected-note {{Assuming 'addr' is not equal to 0}}
                  // expected-note@-1 {{Taking false branch}}
    s->channel = data < 3 ? data : 0;
  } else if (addr == 4) { // expected-note {{Assuming 'addr' is equal to 4}}
                          // expected-note@-1 {{Taking true branch}}
    s->channels[s->channel] = 1; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}} expected-note {{MMIO stored field 'channel' is guest-controlled}}
                                 // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
  }
}

static const MemoryRegionOps mmio_persistent_clamped_channel_ops = {
    .write = mmio_persistent_clamped_channel,
};

static const MemoryRegionOps mmio_persistent_off_by_one_channel_ops = {
    .write = mmio_persistent_off_by_one_channel,
};

static void mmio_persistent_guarded_channel(void *opaque, uint64_t addr,
                                            uint64_t data, unsigned size) {
  PersistentChannelState *s = opaque;
  if (addr == 0) {
    if (data < 2)
      s->channel = data;
  } else if (addr == 4) {
    s->channels[s->channel] = 1;
  }
}

static const MemoryRegionOps mmio_persistent_guarded_channel_ops = {
    .write = mmio_persistent_guarded_channel,
};

static int persistent_bounded_field_in_unsafe_expression(
    PersistentChannelState *s) {
  return s->channels[s->channel * 4]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}} expected-note {{MMIO stored field 'channel' is guest-controlled}}
                                      // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

typedef struct PersistentMaskedState {
  unsigned control;
  int rates[4];
} PersistentMaskedState;

static const VMStateField migrated_masked_fields[] = {
    VMSTATE_UINT32(control, PersistentMaskedState),
    VMSTATE_END_OF_LIST(),
};

static int migrated_masked_shift_index(PersistentMaskedState *s) {
  return s->rates[(s->control & 0x3000) >> 12];
}

typedef struct MigratedIndexState {
  unsigned index;
  unsigned char byte_index;
  int slots[4];
  int byte_slots[256];
} MigratedIndexState;

static const VMStateField migrated_index_fields[] = {
    VMSTATE_UINT32(index, MigratedIndexState),
    VMSTATE_UINT8(byte_index, MigratedIndexState),
    VMSTATE_END_OF_LIST(),
};

static int migrated_persistent_index(MigratedIndexState *s) {
  return s->slots[s->index]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}} expected-note {{migration stored field 'index' is guest-controlled}}
                             // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static int migrated_bounded_byte_index(MigratedIndexState *s) {
  return s->byte_slots[s->byte_index];
}

typedef struct MigratedAliasState {
  unsigned short next_channel;
  unsigned packet_index;
  unsigned packet_length;
  int packets[8];
  int registers[64];
  unsigned char payload[8];
} MigratedAliasState;

static const VMStateField migrated_alias_fields[] = {
    VMSTATE_UINT16(next_channel, MigratedAliasState),
    VMSTATE_UINT32(packet_index, MigratedAliasState),
    VMSTATE_UINT32(packet_length, MigratedAliasState),
    VMSTATE_END_OF_LIST(),
};

static int migrated_assignment_alias(MigratedAliasState *s) {
  unsigned channel;
  channel = s->next_channel; // expected-note {{migration stored field 'next_channel' is guest-controlled}}
  return s->packets[channel]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count (value [8, 65535], elements 8, source migration-stored field 'next_channel')}}
                              // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static int migrated_index_helper(MigratedAliasState *s, unsigned index) {
  return s->registers[index]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count (value [64, 4294967295], elements 64, source migration-stored field 'packet_index')}}
                              // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static int migrated_argument_alias(MigratedAliasState *s) {
  return migrated_index_helper( // expected-note {{Calling 'migrated_index_helper'}}
      s, s->packet_index); // expected-note {{migration stored field 'packet_index' is guest-controlled}}
}

static void migrated_packet_length_alias(MigratedAliasState *s) {
  unsigned length;
  length = s->packet_length; // expected-note {{migration stored field 'packet_length' is guest-controlled}}
  qemu_send_packet(s, s->payload, length); // expected-warning {{Level B: guest-controlled packet length may exceed the host object extent (value [9, 4294967295], bytes 8, source migration-stored field 'packet_length')}}
                                           // expected-note@-1 {{Level B: guest-controlled packet length may exceed the host object extent}}
}

static int migrated_constant_compound_alias(MigratedAliasState *s) {
  unsigned index;
  index = s->packet_index; // expected-note {{migration stored field 'packet_index' is guest-controlled}}
  index &= 255;
  return s->registers[index]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count (value [64, 255], elements 64, source migration-stored field 'packet_index')}}
                              // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static int migrated_mixed_compound_alias(MigratedAliasState *s) {
  unsigned index;
  index = s->packet_index; // expected-note {{migration stored field 'packet_index' is guest-controlled}}
  index &= s->next_channel; // expected-note {{migration stored field 'next_channel' is guest-controlled}}
  return s->registers[index]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count (value [64, 65535], elements 64)}}
                              // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static int migrated_guarded_assignment_alias(MigratedAliasState *s) {
  unsigned channel;
  channel = s->next_channel;
  if (channel >= 8)
    return 0;
  return s->packets[channel];
}

static int trusted_local_migrated_record(unsigned index) {
  MigratedAliasState local = {0};
  unsigned copied_index;
  local.packet_index = index;
  copied_index = local.packet_index;
  return local.registers[copied_index];
}

typedef struct ValidatedMigratedIndexState {
  unsigned index;
  unsigned count;
  int *slots;
} ValidatedMigratedIndexState;

static _Bool migrated_index_within_count(void *opaque, int version) {
  ValidatedMigratedIndexState *s = opaque;
  return s->index <= s->count;
}

static const VMStateField validated_migrated_index_fields[] = {
    VMSTATE_UINT32(index, ValidatedMigratedIndexState),
    VMSTATE_UINT32(count, ValidatedMigratedIndexState),
    VMSTATE_VALIDATE("index <= count", migrated_index_within_count),
    VMSTATE_END_OF_LIST(),
};

static void allocate_validated_migrated_index(
    ValidatedMigratedIndexState *s) {
  s->slots = malloc(s->count * sizeof(*s->slots));
}

static int migrated_validated_dynamic_index(
    ValidatedMigratedIndexState *s) {
  if (s->index == s->count)
    return 0;
  return s->slots[s->index];
}

static int migrated_validated_cross_object_index(
    ValidatedMigratedIndexState *array,
    ValidatedMigratedIndexState *selector) {
  if (selector->index == array->count) // expected-note {{migration stored field 'index' is guest-controlled}} expected-note {{Assuming field 'index' is not equal to field 'count'}} expected-note {{Taking false branch}}
    return 0;
  return array->slots[selector->index]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                                         // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

typedef struct WeaklyValidatedMigratedIndexState {
  unsigned index;
  unsigned count;
  int *slots;
} WeaklyValidatedMigratedIndexState;

static _Bool migrated_index_one_past_count(void *opaque, int version) {
  WeaklyValidatedMigratedIndexState *s = opaque;
  return s->index <= s->count + 1;
}

static const VMStateField weakly_validated_migrated_index_fields[] = {
    VMSTATE_UINT32(index, WeaklyValidatedMigratedIndexState),
    VMSTATE_UINT32(count, WeaklyValidatedMigratedIndexState),
    VMSTATE_VALIDATE("index <= count + 1", migrated_index_one_past_count),
    VMSTATE_END_OF_LIST(),
};

static void allocate_weakly_validated_migrated_index(
    WeaklyValidatedMigratedIndexState *s) {
  s->slots = malloc(s->count * sizeof(*s->slots));
}

static int migrated_weakly_validated_dynamic_index(
    WeaklyValidatedMigratedIndexState *s) {
  if (s->index == s->count) // expected-note {{migration stored field 'index' is guest-controlled}} expected-note {{Assuming field 'index' is not equal to field 'count'}} expected-note {{Taking false branch}}
    return 0;
  return s->slots[s->index]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                              // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

typedef struct PostLoadBoundedIndexState {
  int index;
  int slots[4];
} PostLoadBoundedIndexState;

static int validate_post_load_index(void *opaque, int version) {
  PostLoadBoundedIndexState *s = opaque;
  if (s->index < 0 || s->index >= 4)
    return -1;
  return 0;
}

static const VMStateDescription post_load_bounded_index_vmsd = {
    .post_load = validate_post_load_index,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT32(index, PostLoadBoundedIndexState),
        VMSTATE_END_OF_LIST(),
    },
};

static int migrated_post_load_bounded_index(PostLoadBoundedIndexState *s) {
  return s->slots[s->index];
}

typedef struct PostLoadUpperOnlyState {
  int index;
  int slots[4];
} PostLoadUpperOnlyState;

static int validate_post_load_upper_only(void *opaque, int version) {
  PostLoadUpperOnlyState *s = opaque;
  if (s->index >= 4)
    return -1;
  return 0;
}

static const VMStateDescription post_load_upper_only_vmsd = {
    .post_load = validate_post_load_upper_only,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT32(index, PostLoadUpperOnlyState),
        VMSTATE_END_OF_LIST(),
    },
};

static int migrated_post_load_upper_only_index(PostLoadUpperOnlyState *s) {
  return s->slots[s->index]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}} expected-note {{migration stored field 'index' is guest-controlled}}
                              // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

typedef struct PostLoadOffByOneIndexState {
  int index;
  int slots[4];
} PostLoadOffByOneIndexState;

static int validate_post_load_off_by_one(void *opaque, int version) {
  PostLoadOffByOneIndexState *s = opaque;
  if (s->index < 0 || s->index > 4)
    return -1;
  return 0;
}

static const VMStateDescription post_load_off_by_one_vmsd = {
    .post_load = validate_post_load_off_by_one,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT32(index, PostLoadOffByOneIndexState),
        VMSTATE_END_OF_LIST(),
    },
};

static int migrated_post_load_off_by_one_index(
    PostLoadOffByOneIndexState *s) {
  return s->slots[s->index]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}} expected-note {{migration stored field 'index' is guest-controlled}}
                              // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static int migrated_post_load_excludes_limit(PostLoadOffByOneIndexState *s) {
  if (s->index == 4)
    return 0;
  return s->slots[s->index];
}

typedef struct PostLoadEarlyAccessState {
  int index;
  int slots[4];
} PostLoadEarlyAccessState;

static int validate_post_load_after_access(void *opaque, int version) {
  PostLoadEarlyAccessState *s = opaque;
  int result = s->slots[s->index]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}} expected-note {{migration stored field 'index' is guest-controlled}}
                                    // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
  if (s->index < 0 || s->index >= 4)
    return -1;
  return result;
}

static const VMStateDescription post_load_early_access_vmsd = {
    .post_load = validate_post_load_after_access,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT32(index, PostLoadEarlyAccessState),
        VMSTATE_END_OF_LIST(),
    },
};

typedef struct AlternateUnvalidatedState {
  int index;
  int slots[4];
} AlternateUnvalidatedState;

static int validate_alternate_index(void *opaque, int version) {
  AlternateUnvalidatedState *s = opaque;
  if (s->index < 0 || s->index >= 4)
    return -1;
  return 0;
}

static const VMStateDescription validated_alternate_vmsd = {
    .post_load = validate_alternate_index,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT32(index, AlternateUnvalidatedState),
        VMSTATE_END_OF_LIST(),
    },
};

static const VMStateDescription unvalidated_alternate_vmsd = {
    .fields = (const VMStateField[]) {
        VMSTATE_UINT32(index, AlternateUnvalidatedState),
        VMSTATE_END_OF_LIST(),
    },
};

static int migrated_alternate_unvalidated_index(AlternateUnvalidatedState *s) {
  return s->slots[s->index]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}} expected-note {{migration stored field 'index' is guest-controlled}}
                              // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

typedef struct PostLoadMMIOOverrideState {
  int index;
  int slots[4];
} PostLoadMMIOOverrideState;

static int validate_post_load_mmio_override(void *opaque, int version) {
  PostLoadMMIOOverrideState *s = opaque;
  if (s->index < 0 || s->index >= 4)
    return -1;
  return 0;
}

static const VMStateDescription post_load_mmio_override_vmsd = {
    .post_load = validate_post_load_mmio_override,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT32(index, PostLoadMMIOOverrideState),
        VMSTATE_END_OF_LIST(),
    },
};

static void mmio_overrides_post_load_index(void *opaque, uint64_t addr,
                                           uint64_t data, unsigned size) {
  PostLoadMMIOOverrideState *s = opaque;
  if (addr == 0) { // expected-note {{Assuming 'addr' is not equal to 0}} expected-note {{Taking false branch}}
    s->index = data;
  } else if (addr == 4) { // expected-note {{Assuming 'addr' is equal to 4}} expected-note {{Taking true branch}}
    s->slots[s->index] = 1; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}} expected-note {{mixed guest input stored field 'index' is guest-controlled}}
                             // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
  }
}

static const MemoryRegionOps mmio_overrides_post_load_index_ops = {
    .write = mmio_overrides_post_load_index,
};

static uint64_t mmio_index(void *opaque, uint64_t addr, unsigned size) { // expected-note {{MMIO callback parameter 'addr' is guest-controlled}}
  int registers[4] = {0};
  return registers[addr]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                          // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

typedef struct MemberArrayState {
  int registers[4];
} MemberArrayState;

static uint64_t mmio_member_index(void *opaque, uint64_t addr, // expected-note {{MMIO callback parameter 'addr' is guest-controlled}}
                                  unsigned size) {
  MemberArrayState *s = opaque;
  return s->registers[addr]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                             // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static uint64_t mmio_bounded_index(void *opaque, uint64_t addr,
                                   unsigned size) {
  int registers[4] = {0};
  if (addr >= 4)
    return 0;
  return registers[addr];
}

static uint64_t mmio_modulo_bounded_index(void *opaque, uint64_t addr,
                                          unsigned size) {
  int registers[12] = {0};
  addr = addr % 0x30;
  addr >>= 2;
  return registers[addr];
}

static const MemoryRegionOps mmio_modulo_bounded_index_ops = {
    .read = mmio_modulo_bounded_index,
};

static uint64_t mmio_modulo_off_by_one_index( // expected-note {{MMIO callback parameter 'addr' is guest-controlled}}
    void *opaque, uint64_t addr, unsigned size) {
  int registers[12] = {0};
  addr = addr % 0x34;
  addr >>= 2;
  return registers[addr]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                          // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static const MemoryRegionOps mmio_modulo_off_by_one_index_ops = {
    .read = mmio_modulo_off_by_one_index,
};

static const MemoryRegionOps mmio_ops = {
    .read = mmio_index,
    .write = mmio_copy,
};

static const MemoryRegionOps mmio_member_ops = {
    .read = mmio_member_index,
};

typedef struct DynamicMemberState {
  int *registers;
  size_t register_count;
  size_t register_base;
} DynamicMemberState;

static void allocate_dynamic_member(DynamicMemberState *s) {
  s->registers = malloc(s->register_count * sizeof(*s->registers));
}

static uint64_t mmio_dynamic_member_index( // expected-note {{MMIO callback parameter 'addr' is guest-controlled}}
    void *opaque, uint64_t addr, unsigned size) {
  DynamicMemberState *s = opaque;
  return s->registers[addr]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                             // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static const MemoryRegionOps mmio_dynamic_member_ops = {
    .read = mmio_dynamic_member_index,
};

static uint64_t mmio_bounded_dynamic_member_index(
    void *opaque, uint64_t addr, unsigned size) {
  DynamicMemberState *s = opaque;
  if (addr >= s->register_count)
    return 0;
  return s->registers[addr];
}

static const MemoryRegionOps mmio_bounded_dynamic_member_ops = {
    .read = mmio_bounded_dynamic_member_index,
};

static uint64_t mmio_scaled_dynamic_member_index(
    void *opaque, uint64_t addr, unsigned size) {
  DynamicMemberState *s = opaque;
  if (addr < s->register_base)
    return 0;
  if (addr >= s->register_base + (s->register_count << 2))
    return 0;
  size_t absolute =
      s->register_base + ((addr - s->register_base) >> 2);
  size_t offset = absolute - s->register_base;
  return s->registers[offset];
}

static const MemoryRegionOps mmio_scaled_dynamic_member_ops = {
    .read = mmio_scaled_dynamic_member_index,
};

static uint64_t mmio_range_helper_index(void *opaque, uint64_t addr,
                                        unsigned size) {
  int registers[4] = {0};
  if (!range_covers_byte(8, sizeof(registers), addr))
    return 0;
  return registers[(addr - 8) / sizeof(registers[0])];
}

static const MemoryRegionOps mmio_range_helper_ops = {
    .read = mmio_range_helper_index,
};

static uint64_t mmio_oversized_range_helper_index( // expected-note {{MMIO callback parameter 'addr' is guest-controlled}}
    void *opaque, uint64_t addr, unsigned size) {
  int registers[4] = {0};
  if (!range_covers_byte(8, 2 * sizeof(registers), addr)) // expected-note {{Taking false branch}}
    return 0;
  return registers[(addr - 8) / sizeof(registers[0])]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                                                       // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static const MemoryRegionOps mmio_oversized_range_helper_ops = {
    .read = mmio_oversized_range_helper_index,
};

static inline _Bool shifted_register_exists(uint64_t reg) {
  return (reg >> 4) < 4;
}

static uint64_t mmio_shifted_predicate_index(void *opaque, uint64_t addr,
                                             unsigned size) {
  int registers[4] = {0};
  uint64_t reg = addr & ~(uint64_t)0xf;
  if (!shifted_register_exists(reg))
    return 0;
  return registers[reg >> 4];
}

static const MemoryRegionOps mmio_shifted_predicate_ops = {
    .read = mmio_shifted_predicate_index,
};

static inline _Bool oversized_shifted_register_exists(uint64_t reg) {
  return (reg >> 4) < 8;
}

static uint64_t mmio_oversized_shifted_predicate_index( // expected-note {{MMIO callback parameter 'addr' is guest-controlled}}
    void *opaque, uint64_t addr, unsigned size) {
  int registers[4] = {0};
  uint64_t reg = addr & ~(uint64_t)0xf;
  if (!oversized_shifted_register_exists(reg)) // expected-note {{Taking false branch}}
    return 0;
  return registers[reg >> 4]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                               // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static const MemoryRegionOps mmio_oversized_shifted_predicate_ops = {
    .read = mmio_oversized_shifted_predicate_index,
};

static uint64_t mmio_absolute_dynamic_member_index( // expected-note {{MMIO callback parameter 'addr' is guest-controlled}}
    void *opaque, uint64_t addr, unsigned size) {
  DynamicMemberState *s = opaque;
  if (addr < s->register_base) // expected-note {{Assuming 'addr' is >= field 'register_base'}}
                               // expected-note@-1 {{Taking false branch}}
    return 0;
  if (addr >= s->register_base + (s->register_count << 2)) // expected-note {{Assuming the condition is false}}
                                                           // expected-note@-1 {{Taking false branch}}
    return 0;
  size_t absolute =
      s->register_base + ((addr - s->register_base) >> 2);
  return s->registers[absolute]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                                 // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static const MemoryRegionOps mmio_absolute_dynamic_member_ops = {
    .read = mmio_absolute_dynamic_member_index,
};

static uint64_t mmio_registered_bounded_index(void *opaque, uint64_t addr,
                                              unsigned size) {
  int registers[4] = {0};
  return registers[addr / 4];
}

static const MemoryRegionOps mmio_registered_bounded_ops = {
    .read = mmio_registered_bounded_index,
};

static MemoryRegion mmio_registered_bounded_region;

static void register_bounded_mmio(void) {
  memory_region_init_io(&mmio_registered_bounded_region, 0,
                        &mmio_registered_bounded_ops, 0, "bounded", 16);
}

static uint64_t mmio_registered_oversized_index( // expected-note {{MMIO callback parameter 'addr' is guest-controlled}}
    void *opaque, uint64_t addr, unsigned size) {
  int registers[4] = {0};
  return registers[addr / 4]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                               // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static const MemoryRegionOps mmio_registered_oversized_ops = {
    .read = mmio_registered_oversized_index,
};

static MemoryRegion mmio_registered_oversized_region;

static void register_oversized_mmio(void) {
  memory_region_init_io(&mmio_registered_oversized_region, 0,
                        &mmio_registered_oversized_ops, 0, "oversized", 32);
}

static uint64_t mmio_registered_span(void *opaque, uint64_t addr,
                                     unsigned size) {
  unsigned char registers[16] = {0};
  uint64_t result = 0;
  for (unsigned i = 0; i < size; ++i)
    result += registers[addr + i];
  return result;
}

static const MemoryRegionOps mmio_registered_span_ops = {
    .read = mmio_registered_span,
};

static MemoryRegion mmio_registered_span_region;

static void register_span_mmio(void) {
  memory_region_init_io(&mmio_registered_span_region, 0,
                        &mmio_registered_span_ops, 0, "span", 16);
}

static uint64_t mmio_registered_off_by_one_span( // expected-note {{MMIO callback parameter 'addr' is guest-controlled}}
    void *opaque, uint64_t addr, unsigned size) {
  unsigned char registers[16] = {0};
  return registers[addr + size]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                                  // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static const MemoryRegionOps mmio_registered_off_by_one_span_ops = {
    .read = mmio_registered_off_by_one_span,
};

static MemoryRegion mmio_registered_off_by_one_span_region;

static void register_off_by_one_span_mmio(void) {
  memory_region_init_io(&mmio_registered_off_by_one_span_region, 0,
                        &mmio_registered_off_by_one_span_ops, 0, "span-oob",
                        16);
}

static const MemoryRegionOps mmio_definite_ops = {
    .write = mmio_definite_copy,
};

static void mmio_allocation(void *opaque, uint64_t addr, uint64_t data, // expected-note {{MMIO callback parameter 'data' is guest-controlled}}
                            unsigned size) {
  malloc(data * size); // expected-warning {{Level B: guest-controlled allocation-size arithmetic may overflow}}
                       // expected-note@-1 {{Level B: guest-controlled allocation-size arithmetic may overflow}}
}

static void mmio_bounded_allocation(void *opaque, uint64_t addr,
                                    uint64_t data, unsigned size) {
  if (data > 1024 || size > 8)
    return;
  malloc(data * size);
}

static const MemoryRegionOps mmio_allocation_ops = {
    .write = mmio_allocation,
};

static const MemoryRegionOps mmio_bounded_allocation_ops = {
    .write = mmio_bounded_allocation,
};

static void mmio_definite_allocation(void *opaque, uint64_t addr, // expected-note {{MMIO callback parameter 'data' is guest-controlled}}
                                     uint64_t data, unsigned size) {
  if (data <= ((uint64_t)-1) / 2) // expected-note {{Assuming the condition is false}}
                                  // expected-note@-1 {{Taking false branch}}
    return;
  malloc(data + data); // expected-warning {{Level B: guest-controlled allocation-size arithmetic overflows}}
                       // expected-note@-1 {{Level B: guest-controlled allocation-size arithmetic overflows}}
}

static const MemoryRegionOps mmio_definite_allocation_ops = {
    .write = mmio_definite_allocation,
};

static void mmio_heap_copy(void *opaque, uint64_t addr, uint64_t data, // expected-note {{MMIO callback parameter 'size' is guest-controlled}}
                           unsigned size) {
  char *destination = malloc(4);
  if (!destination) // expected-note {{Assuming 'destination' is non-null}}
                    // expected-note@-1 {{Taking false branch}}
    return;
  memcpy(destination, opaque, size); // expected-warning {{Level B: guest-controlled memory-operation length may exceed the host object extent}}
                                     // expected-note@-1 {{Level B: guest-controlled memory-operation length may exceed the host object extent}}
}

static const MemoryRegionOps mmio_heap_copy_ops = {
    .write = mmio_heap_copy,
};

static void mmio_memmove_length( // expected-note {{MMIO callback parameter 'size' is guest-controlled}}
    void *opaque, uint64_t addr, uint64_t data, unsigned size) {
  char destination[4];
  memmove(destination, opaque, size); // expected-warning {{Level B: guest-controlled memory-operation length may exceed the host object extent}}
                                      // expected-note@-1 {{Level B: guest-controlled memory-operation length may exceed the host object extent}}
}

static const MemoryRegionOps mmio_memmove_length_ops = {
    .write = mmio_memmove_length,
};

static void mmio_guest_physical_address_only(void *opaque, uint64_t addr,
                                             uint64_t data, unsigned size) {
  char destination[4];
  dma_memory_read(opaque, addr, destination, sizeof(destination), 0);
}

static const MemoryRegionOps mmio_guest_physical_address_only_ops = {
    .write = mmio_guest_physical_address_only,
};

static void mmio_offset_copy(void *opaque, uint64_t addr, uint64_t data, // expected-note {{MMIO callback parameter 'addr' is guest-controlled}}
                             unsigned size) {
  char destination[16];
  if (addr >= sizeof(destination)) // expected-note {{Assuming the condition is false}}
                                   // expected-note@-1 {{Taking false branch}}
    return;
  memcpy(destination + addr, opaque, size); // expected-warning {{Level B: guest-controlled memory-operation offset plus length may exceed the host object extent}}
                                            // expected-note@-1 {{Level B: guest-controlled memory-operation offset plus length may exceed the host object extent}}
}

static const MemoryRegionOps mmio_offset_copy_ops = {
    .write = mmio_offset_copy,
};

typedef struct TailMemberArrayState {
  unsigned char bytes[2048];
} TailMemberArrayState;

static void mmio_member_array_tail(void *opaque, uint64_t addr, uint64_t data,
                                   unsigned size) {
  TailMemberArrayState *s = opaque;
  size_t frame_length = data & 63;
  if (frame_length < 60)
    memset(&s->bytes[frame_length + 2], 0, 60 - frame_length);
}

static const MemoryRegionOps mmio_member_array_tail_ops = {
    .write = mmio_member_array_tail,
};

static void mmio_member_array_tail_oob( // expected-note {{MMIO callback parameter 'data' is guest-controlled}}
    void *opaque, uint64_t addr, uint64_t data,
    unsigned size) {
  TailMemberArrayState *s = opaque;
  size_t offset = 2040 + (data & 7);
  size_t length = 9;
  memset(&s->bytes[offset], 0, length); // expected-warning {{Level A: guest-controlled memory-operation offset plus length exceeds the host object extent}}
                                       // expected-note@-1 {{Level A: guest-controlled memory-operation offset plus length exceeds the host object extent}}
}

static const MemoryRegionOps mmio_member_array_tail_oob_ops = {
    .write = mmio_member_array_tail_oob,
};

static char framework_bounded_buffer[16];

static void mmio_framework_bounded_copy(void *opaque, uint64_t addr,
                                        uint64_t data, unsigned size) {
  memcpy(&framework_bounded_buffer[addr], &data, size);
}

static const MemoryRegionOps mmio_framework_bounded_copy_ops = {
    .write = mmio_framework_bounded_copy,
};

static MemoryRegion framework_bounded_region;

static void register_framework_bounded_copy(void) {
  memory_region_init_io(&framework_bounded_region, 0,
                        &mmio_framework_bounded_copy_ops,
                        framework_bounded_buffer, "bounded", 16);
}

static void mmio_bounded_tail_fill(void *opaque, uint64_t addr,
                                   uint64_t data, unsigned size) {
  char destination[16];
  if (size >= sizeof(destination))
    return;
  memset(&destination[size], 0, sizeof(destination) - size);
}

static const MemoryRegionOps mmio_bounded_tail_fill_ops = {
    .write = mmio_bounded_tail_fill,
};

static int byte_data_result;

static void mmio_byte_data_index(void *opaque, uint64_t addr, uint64_t data,
                                 unsigned size) {
  int channels[3] = {0};
  unsigned channel = data >> 6;
  if (channel == 3)
    return;
  byte_data_result = channels[channel];
}

static const MemoryRegionOps mmio_byte_data_index_ops = {
    .write = mmio_byte_data_index,
    .impl = {
        .min_access_size = 1,
        .max_access_size = 1,
    },
};

static void mmio_word_data_index(void *opaque, uint64_t addr, uint64_t data, // expected-note {{MMIO callback parameter 'data' is guest-controlled}}
                                 unsigned size) {
  int channels[3] = {0};
  unsigned channel = data >> 6;
  if (channel == 3) // expected-note {{Taking false branch}} expected-note {{Assuming 'channel' is not equal to 3}}
    return;
  byte_data_result = channels[channel]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                                        // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static const MemoryRegionOps mmio_word_data_index_ops = {
    .write = mmio_word_data_index,
    .impl = {
        .min_access_size = 2,
        .max_access_size = 2,
    },
};

static void mmio_signed_length(void *opaque, uint64_t addr, uint64_t data, // expected-note {{MMIO callback parameter 'data' is guest-controlled}}
                               unsigned size) {
  char destination[8];
  int length = (int)data;
  memcpy(destination, opaque, (size_t)length); // expected-warning {{Level B: guest-controlled memory-operation length may exceed the host object extent}}
                                               // expected-note@-1 {{Level B: guest-controlled memory-operation length may exceed the host object extent}}
}

static const MemoryRegionOps mmio_signed_length_ops = {
    .write = mmio_signed_length,
};

static void mmio_truncated_allocation(void *opaque, uint64_t addr, // expected-note {{MMIO callback parameter 'data' is guest-controlled}}
                                      uint64_t data, unsigned size) {
  unsigned short allocation_size = (unsigned short)data;
  char *destination = malloc(allocation_size);
  if (!destination) // expected-note {{Assuming 'destination' is non-null}}
                    // expected-note@-1 {{Taking false branch}}
    return;
  memcpy(destination, opaque, data); // expected-warning {{Level B: guest-controlled memory-operation length may exceed the host object extent}}
                                     // expected-note@-1 {{Level B: guest-controlled memory-operation length may exceed the host object extent}}
}

static const MemoryRegionOps mmio_truncated_allocation_ops = {
    .write = mmio_truncated_allocation,
};

static void mmio_dma_index(void *opaque, uint64_t addr, uint64_t data,
                           unsigned size) {
  unsigned index;
  int slots[4] = {0};
  if (dma_memory_read(opaque, addr, &index, sizeof(index), 0) != 0) // expected-note {{DMA populated guest-controlled data here}}
                                                                      // expected-note@-1 {{Taking false branch}}
    return;
  slots[index] = 1; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                    // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static void mmio_failed_dma_is_not_a_source(void *opaque, uint64_t addr,
                                            uint64_t data, unsigned size) {
  unsigned index;
  int slots[4] = {0};
  if (dma_memory_read(opaque, addr, &index, sizeof(index), 0) == 0)
    return;
  slots[index] = 1;
}

static unsigned legacy_dma_index(uint64_t address) {
  unsigned index;
  int slots[4] = {0};
  physical_memory_read(address, &index, sizeof(index)); // expected-note {{DMA populated guest-controlled data here}}
  return slots[index]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                       // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static const MemoryRegionOps mmio_dma_ops = {
    .write = mmio_dma_index,
};

static const MemoryRegionOps mmio_failed_dma_ops = {
    .write = mmio_failed_dma_is_not_a_source,
};

static unsigned migration_index(void *file) {
  unsigned index;
  int slots[4] = {0};
  if (qemu_get_buffer(file, (unsigned char *)&index, sizeof(index)) != // expected-note {{migration populated guest-controlled data here}}
      sizeof(index))
    // expected-note@-2 {{Taking false branch}}
    return 0;
  return slots[index]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                       // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static unsigned byte_index_covers_whole_table(void *file) {
  unsigned char index;
  int slots[256] = {0};
  if (qemu_get_buffer(file, &index, sizeof(index)) != sizeof(index))
    return 0;
  return slots[index];
}

static void migration_copy_length(void *file) {
  char destination[8];
  unsigned length = qemu_get_byte(file); // expected-note {{migration scalar is guest-controlled}}
  qemu_get_buffer(file, (unsigned char *)destination, length); // expected-warning {{Level B: guest-controlled memory-operation length may exceed the host object extent}}
                                                               // expected-note@-1 {{Level B: guest-controlled memory-operation length may exceed the host object extent}}
}

static void qemu_iovec_copy_length(void *qiov, void *file) {
  char destination[8];
  unsigned length = qemu_get_byte(file); // expected-note {{migration scalar is guest-controlled}}
  qemu_iovec_to_buf(qiov, 0, destination, length); // expected-warning {{Level B: guest-controlled memory-operation length may exceed the host object extent}}
                                                   // expected-note@-1 {{Level B: guest-controlled memory-operation length may exceed the host object extent}}
}

static unsigned disk_image_index(void *child) {
  unsigned index;
  int slots[4] = {0};
  if (bdrv_pread(child, 0, sizeof(index), &index, 0) != 0) // expected-note {{disk-image read populated guest-controlled data here}}
                                                          // expected-note@-1 {{Taking false branch}}
    return 0;
  return slots[index]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                       // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static long network_index(NetClientState *client, const unsigned char *packet,
                          size_t length) {
  int slots[4] = {0};
  if (length < 2) // expected-note {{Assuming 'length' is >= 2}}
                   // expected-note@-1 {{Taking false branch}}
    return 0;
  return slots[packet[1]]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                           // expected-note@-1 {{network receive callback parameter 'packet' is guest-controlled}}
                           // expected-note@-2 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static const NetClientInfo network_info = {
    .receive = network_index,
};

static void pio_index(void *opaque, unsigned address, unsigned data) { // expected-note {{PIO callback parameter 'address' is guest-controlled}}
  int registers[2] = {0};
  registers[address] = data; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                             // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static const MemoryRegionPortio pio_ops[] = {
    {.offset = 0, .len = 2, .size = 1, .write = pio_index},
    {0},
};

static void same_signature_but_not_registered(void *opaque, uint64_t addr,
                                              uint64_t data, unsigned size) {
  char destination[8];
  memcpy(destination, opaque, size);
}

typedef struct FlexiblePacket {
  unsigned tag;
  unsigned char data[];
} FlexiblePacket;

static void mmio_flexible_array_oob(void *opaque, uint64_t addr, // expected-note {{MMIO callback parameter 'data' is guest-controlled}}
                                    uint64_t data, unsigned size) {
  FlexiblePacket *packet = malloc(sizeof(*packet) + 4);
  if (!packet) // expected-note {{Assuming 'packet' is non-null}}
               // expected-note@-1 {{Taking false branch}}
    return;
  unsigned index = 4 + (data & 3);
  packet->data[index] = 1; // expected-warning {{Level A: guest-controlled array index exceeds the host object element count}}
                           // expected-note@-1 {{Level A: guest-controlled array index exceeds the host object element count}}
}

static void mmio_flexible_array_guarded(void *opaque, uint64_t addr,
                                        uint64_t data, unsigned size) {
  FlexiblePacket *packet = malloc(sizeof(*packet) + 4);
  if (!packet)
    return;
  unsigned index = data & 255;
  if (index >= 4)
    return;
  packet->data[index] = 1;
}

static void mmio_flexible_array_copy_oob(void *opaque, uint64_t addr, // expected-note {{MMIO callback parameter 'data' is guest-controlled}}
                                         uint64_t data, unsigned size) {
  FlexiblePacket *packet = malloc(sizeof(*packet) + 4);
  if (!packet) // expected-note {{Assuming 'packet' is non-null}}
               // expected-note@-1 {{Taking false branch}}
    return;
  size_t length = 5 + (data & 3);
  memset(packet->data, 0, length); // expected-warning {{Level A: guest-controlled memory-operation length exceeds the host object extent}}
                                   // expected-note@-1 {{Level A: guest-controlled memory-operation length exceeds the host object extent}}
}

static void mmio_flexible_array_copy_guarded(void *opaque, uint64_t addr,
                                             uint64_t data, unsigned size) {
  FlexiblePacket *packet = malloc(sizeof(*packet) + 4);
  if (!packet)
    return;
  size_t length = data & 255;
  if (length > 4)
    return;
  memset(packet->data, 0, length);
}

static const MemoryRegionOps mmio_flexible_array_oob_ops = {
    .write = mmio_flexible_array_oob,
};

static const MemoryRegionOps mmio_flexible_array_guarded_ops = {
    .write = mmio_flexible_array_guarded,
};

static const MemoryRegionOps mmio_flexible_array_copy_oob_ops = {
    .write = mmio_flexible_array_copy_oob,
};

static const MemoryRegionOps mmio_flexible_array_copy_guarded_ops = {
    .write = mmio_flexible_array_copy_guarded,
};

static void mmio_test_bit_oob(void *opaque, uint64_t addr, uint64_t data, // expected-note {{MMIO callback parameter 'data' is guest-controlled}}
                              unsigned size) {
  unsigned long bitmap[1] = {0};
  long bit = (long)(sizeof(bitmap) * 8 + (data & 7));
  (void)test_bit(bit, bitmap); // expected-warning {{Level A: guest-controlled bitmap bit index exceeds the host object bit capacity}}
                               // expected-note@-1 {{Level A: guest-controlled bitmap bit index exceeds the host object bit capacity}}
}

static void mmio_set_bit_oob(void *opaque, uint64_t addr, uint64_t data, // expected-note {{MMIO callback parameter 'data' is guest-controlled}}
                             unsigned size) {
  unsigned long bitmap[1] = {0};
  long bit = (long)(sizeof(bitmap) * 8 + (data & 7));
  set_bit(bit, bitmap); // expected-warning {{Level A: guest-controlled bitmap bit index exceeds the host object bit capacity}}
                        // expected-note@-1 {{Level A: guest-controlled bitmap bit index exceeds the host object bit capacity}}
}

static void mmio_clear_bit_oob(void *opaque, uint64_t addr, uint64_t data, // expected-note {{MMIO callback parameter 'data' is guest-controlled}}
                               unsigned size) {
  unsigned long bitmap[1] = {0};
  long bit = (long)(sizeof(bitmap) * 8 + (data & 7));
  clear_bit(bit, bitmap); // expected-warning {{Level A: guest-controlled bitmap bit index exceeds the host object bit capacity}}
                          // expected-note@-1 {{Level A: guest-controlled bitmap bit index exceeds the host object bit capacity}}
}

static void mmio_bitmap_guarded(void *opaque, uint64_t addr, uint64_t data,
                                unsigned size) {
  unsigned long bitmap[1] = {0};
  long bit = (long)(data & 255);
  if ((unsigned long)bit >= sizeof(bitmap) * 8)
    return;
  (void)test_bit(bit, bitmap);
  set_bit(bit, bitmap);
  clear_bit(bit, bitmap);
}

static void mmio_bitmap_overwritten_with_trusted(
    void *opaque, uint64_t addr, uint64_t data, unsigned size) {
  unsigned long bitmap[1] = {0};
  long bit = (long)(sizeof(bitmap) * 8 + (data & 7));
  bit = 0;
  (void)test_bit(bit, bitmap);
}

static void mmio_bitmap_shadowed_local(void *opaque, uint64_t addr,
                                       uint64_t data, unsigned size) {
  unsigned long bitmap[1] = {0};
  long bit = (long)(sizeof(bitmap) * 8 + (data & 7));
  {
    long bit = 0;
    (void)test_bit(bit, bitmap);
  }
  (void)bit;
}

static const MemoryRegionOps mmio_test_bit_oob_ops = {
    .write = mmio_test_bit_oob,
};

static const MemoryRegionOps mmio_set_bit_oob_ops = {
    .write = mmio_set_bit_oob,
};

static const MemoryRegionOps mmio_clear_bit_oob_ops = {
    .write = mmio_clear_bit_oob,
};

static const MemoryRegionOps mmio_bitmap_guarded_ops = {
    .write = mmio_bitmap_guarded,
};

static const MemoryRegionOps mmio_bitmap_overwritten_with_trusted_ops = {
    .write = mmio_bitmap_overwritten_with_trusted,
};

static const MemoryRegionOps mmio_bitmap_shadowed_local_ops = {
    .write = mmio_bitmap_shadowed_local,
};
