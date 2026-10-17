// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.qemu.GuestMemorySafety -analyzer-output=text -verify %s

typedef __SIZE_TYPE__ size_t;
typedef __UINT64_TYPE__ uint64_t;

void *memcpy(void *, const void *, size_t);
void *malloc(size_t);
unsigned dma_memory_read(void *, uint64_t, void *, size_t, unsigned);
void physical_memory_read(uint64_t, void *, uint64_t);
size_t qemu_get_buffer(void *, unsigned char *, size_t);
int bdrv_pread(void *, long long, long long, void *, unsigned);
unsigned qemu_get_byte(void *);
size_t qemu_iovec_to_buf(void *, size_t, void *, size_t);
int range_covers_byte(uint64_t, uint64_t, uint64_t);

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
  long (*receive)(void *, const unsigned char *, size_t);
  long (*receive_iov)(void *, const void *, int);
} NetClientInfo;

static void mmio_copy(void *opaque, uint64_t addr, uint64_t data, // expected-note {{MMIO callback parameter 'size' is guest-controlled}}
                      unsigned size) {
  char destination[8];
  memcpy(destination, opaque, size); // expected-warning {{Level B: guest-controlled memory-operation length may exceed the host object extent}}
                                    // expected-note@-1 {{Level B: guest-controlled memory-operation length may exceed the host object extent}}
}

static void mmio_definite_copy(void *opaque, uint64_t addr, uint64_t data, // expected-note {{MMIO callback parameter 'size' is guest-controlled}}
                               unsigned size) {
  char destination[8];
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
  malloc(data + data); // expected-warning {{Level A: guest-controlled allocation-size arithmetic overflows}}
                       // expected-note@-1 {{Level A: guest-controlled allocation-size arithmetic overflows}}
}

static const MemoryRegionOps mmio_definite_allocation_ops = {
    .write = mmio_definite_allocation,
};

static void mmio_heap_copy(void *opaque, uint64_t addr, uint64_t data, // expected-note {{MMIO callback parameter 'size' is guest-controlled}}
                           unsigned size) {
  char *destination = malloc(8);
  if (!destination) // expected-note {{Assuming 'destination' is non-null}}
                    // expected-note@-1 {{Taking false branch}}
    return;
  memcpy(destination, opaque, size); // expected-warning {{Level B: guest-controlled memory-operation length may exceed the host object extent}}
                                     // expected-note@-1 {{Level B: guest-controlled memory-operation length may exceed the host object extent}}
}

static const MemoryRegionOps mmio_heap_copy_ops = {
    .write = mmio_heap_copy,
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

static long network_index(void *client, const unsigned char *packet, // expected-note {{network receive callback parameter 'packet' is guest-controlled}}
                          size_t length) {
  int slots[4] = {0};
  if (length == 0) // expected-note {{Assuming 'length' is not equal to 0}}
                   // expected-note@-1 {{Taking false branch}}
    return 0;
  return slots[packet[0]]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                           // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
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
