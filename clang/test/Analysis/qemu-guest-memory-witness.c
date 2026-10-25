// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:ReportLevelC=true \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:EnableInitializedByteTracking=true \
// RUN:   -analyzer-output=text %s 2>&1 | \
// RUN:   %python %S/Inputs/qemu-gms-witness-validate.py --expect-absent \
// RUN:   %s qemu-guest-memory-witness.c
// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:ReportLevelC=true \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:EnableInitializedByteTracking=true \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:EmitStructuredWitness=true \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:QEMUSourceRoot=%S \
// RUN:   -analyzer-output=text %s 2>&1 | \
// RUN:   %python %S/Inputs/qemu-gms-witness-validate.py \
// RUN:   %s qemu-guest-memory-witness.c

typedef __SIZE_TYPE__ size_t;
typedef __UINT8_TYPE__ uint8_t;
typedef __UINT32_TYPE__ uint32_t;
typedef __UINT64_TYPE__ uint64_t;
typedef uint64_t hwaddr;

void *memcpy(void *, const void *, size_t);
int memcmp(const void *, const void *, size_t);
void *malloc(size_t);
void *g_malloc(size_t);
int test_bit(long, const unsigned long *);
void set_bit(long, unsigned long *);
void clear_bit(long, unsigned long *);
void consume_address(const void *);
void consume_u32(uint32_t);

typedef struct MemoryRegionOps {
  uint64_t (*read)(void *, uint64_t, unsigned);
  void (*write)(void *, uint64_t, uint64_t, unsigned);
} MemoryRegionOps;

typedef struct NetClientState NetClientState;
typedef struct AddressSpace AddressSpace;
typedef struct QEMUFile QEMUFile;
typedef struct MemTxAttrs {
  unsigned int unspecified : 1;
} MemTxAttrs;
#define MEMTXATTRS_UNSPECIFIED ((MemTxAttrs){0})
typedef struct NetClientInfo {
  long (*receive)(NetClientState *, const unsigned char *, size_t);
} NetClientInfo;

void *address_space_map(AddressSpace *, hwaddr, hwaddr *, _Bool, MemTxAttrs);
void address_space_unmap(AddressSpace *, void *, hwaddr, _Bool, hwaddr);
size_t qemu_get_buffer(QEMUFile *, unsigned char *, size_t);
void qemu_put_buffer(QEMUFile *, const unsigned char *, size_t);

#define DMA_LOAD_U32(pointer) (*(uint32_t *)(pointer))
#define DMA_FORWARD_U32(value) consume_u32(value)
#define DMA_ASSIGN_U32(value)                                                  \
  do {                                                                         \
    result = (value);                                                          \
  } while (0)

static uint64_t result;

// Each marked line must produce exactly one warning. WITNESS cases require a
// full payload, NOT-APPLICABLE cases require an explicit reason record, and the
// UNACCOUNTED negative case must produce neither. Keep each failing value a
// singleton so byte widths cannot hide in ranges.

static void char_read(void *opaque, uint64_t addr, uint64_t data,
                      unsigned size) {
  char slots[4] = {0};
  if (data != 4)
    return;
  result = slots[data]; // WITNESS: char_read
}

static const MemoryRegionOps char_read_ops = {.write = char_read};

static void char_write(void *opaque, uint64_t addr, uint64_t data,
                       unsigned size) {
  char slots[4] = {0};
  if (data != 4)
    return;
  slots[data] = 1; // WITNESS: char_write
}

static const MemoryRegionOps char_write_ops = {.write = char_write};

static void int_read(void *opaque, uint64_t addr, uint64_t data,
                     unsigned size) {
  int slots[4] = {0};
  if (data != 4)
    return;
  result = slots[data]; // WITNESS: int_read
}

static const MemoryRegionOps int_read_ops = {.write = int_read};

static void int_write(void *opaque, uint64_t addr, uint64_t data,
                      unsigned size) {
  int slots[4] = {0};
  if (data != 4)
    return;
  slots[data] = 1; // WITNESS: int_write
}

static const MemoryRegionOps int_write_ops = {.write = int_write};

static void u64_read(void *opaque, uint64_t addr, uint64_t data,
                     unsigned size) {
  uint64_t slots[4] = {0};
  if (data != 4)
    return;
  result = slots[data]; // WITNESS: u64_read
}

static const MemoryRegionOps u64_read_ops = {.write = u64_read};

static void u64_write(void *opaque, uint64_t addr, uint64_t data,
                      unsigned size) {
  uint64_t slots[4] = {0};
  if (data != 4)
    return;
  slots[data] = 1; // WITNESS: u64_write
}

static const MemoryRegionOps u64_write_ops = {.write = u64_write};

static void offset_destination(void *opaque, uint64_t addr, uint64_t data,
                               unsigned size) {
  char bytes[8] = {0};
  if (data != 6)
    return;
  memcpy(bytes + data, opaque, 4); // WITNESS: offset_destination
}

static const MemoryRegionOps offset_destination_ops = {
    .write = offset_destination};

static void offset_source(void *opaque, uint64_t addr, uint64_t data,
                          unsigned size) {
  char bytes[8] = {0};
  if (data != 6)
    return;
  memcpy(opaque, bytes + data, 4); // WITNESS: offset_source
}

static const MemoryRegionOps offset_source_ops = {.write = offset_source};

static long callback_byte(NetClientState *client, const unsigned char *packet,
                          size_t length) {
  if (length != 3)
    return 0;
  return packet[4]; // WITNESS: callback_byte
}

static const NetClientInfo callback_byte_ops = {.receive = callback_byte};

static long callback_scalar(NetClientState *client, const unsigned char *packet,
                            size_t length) {
  if (length != 3)
    return 0;
  return *(const unsigned *)(packet + 4); // WITNESS: callback_scalar
}

static const NetClientInfo callback_scalar_ops = {.receive = callback_scalar};

static long callback_memory(NetClientState *client, const unsigned char *packet,
                            size_t length) {
  if (length != 3)
    return 0;
  return memcmp(packet + 4, "QEMU", 4); // WITNESS: callback_memory
}

static const NetClientInfo callback_memory_ops = {.receive = callback_memory};

static void bitmap_read(void *opaque, uint64_t addr, uint64_t data,
                        unsigned size) {
  unsigned long bitmap[1] = {0};
  long bit = (long)data;
  if (data != sizeof(bitmap) * 8)
    return;
  result = test_bit(bit, bitmap); // WITNESS: bitmap_read
}

static const MemoryRegionOps bitmap_read_ops = {.write = bitmap_read};

static void bitmap_set(void *opaque, uint64_t addr, uint64_t data,
                       unsigned size) {
  unsigned long bitmap[1] = {0};
  long bit = (long)data;
  if (data != sizeof(bitmap) * 8)
    return;
  set_bit(bit, bitmap); // WITNESS: bitmap_set
}

static const MemoryRegionOps bitmap_set_ops = {.write = bitmap_set};

static void bitmap_clear(void *opaque, uint64_t addr, uint64_t data,
                         unsigned size) {
  unsigned long bitmap[1] = {0};
  long bit = (long)data;
  if (data != sizeof(bitmap) * 8)
    return;
  clear_bit(bit, bitmap); // WITNESS: bitmap_clear
}

static const MemoryRegionOps bitmap_clear_ops = {.write = bitmap_clear};

static void address_only(void *opaque, uint64_t addr, uint64_t data,
                         unsigned size) {
  int slots[4] = {0};
  if (data != 5)
    return;
  consume_address(&slots[data]); // NOT-APPLICABLE: address_only
}

static const MemoryRegionOps address_only_ops = {.write = address_only};

static void nested_address_read(void *opaque, uint64_t addr, uint64_t data,
                                unsigned size) {
  int slots[4][2] = {{0}};
  if (data != 4)
    return;
  result = slots[data][0]; // NOT-APPLICABLE: nested_address_read
}

static const MemoryRegionOps nested_address_read_ops = {
    .write = nested_address_read};

static void nested_address_write(void *opaque, uint64_t addr, uint64_t data,
                                 unsigned size) {
  int slots[4][2] = {{0}};
  if (data != 4)
    return;
  slots[data][0] = 1; // NOT-APPLICABLE: nested_address_write
}

static const MemoryRegionOps nested_address_write_ops = {
    .write = nested_address_write};

static void subarray_decay(void *opaque, uint64_t addr, uint64_t data,
                           unsigned size) {
  int slots[4][2] = {{0}};
  if (data != 4)
    return;
  memcpy(opaque,
         slots[data], // NOT-APPLICABLE: subarray_decay
         sizeof(slots[0]));
}

static const MemoryRegionOps subarray_decay_ops = {.write = subarray_decay};

typedef struct WitnessTrailingOne {
  int slots[1];
} WitnessTrailingOne;

static void flexible_tail_allocation(void *opaque, uint64_t addr,
                                     uint64_t data, unsigned size) {
  WitnessTrailingOne *tail =
      malloc(sizeof(*tail) + 3 * sizeof(tail->slots[0]));
  if (!tail || data != 3)
    return;
  // The trailing [1] member is flexible-array-like under the default policy;
  // the concrete allocation provides room for this element.
  tail->slots[data] = 0;
  result = tail->slots[data];
}

static const MemoryRegionOps flexible_tail_allocation_ops = {
    .write = flexible_tail_allocation};

static void smaller_dynamic_array_extent(void *opaque, uint64_t addr,
                                         uint64_t data, unsigned size) {
  int storage[1] = {0};
  int (*slots)[8] = (int(*)[8])storage;
  if (data != 1)
    return;
  result = (*slots)[data]; // WITNESS: smaller_dynamic_array_extent
}

static const MemoryRegionOps smaller_dynamic_array_extent_ops = {
    .write = smaller_dynamic_array_extent};

static void nested_final_read(void *opaque, uint64_t addr, uint64_t data,
                              unsigned size) {
  int slots[4][2] = {{0}};
  if (data != 2)
    return;
  result = slots[0][data]; // WITNESS: nested_final_read
}

static const MemoryRegionOps nested_final_read_ops = {
    .write = nested_final_read};

static void nested_final_write(void *opaque, uint64_t addr, uint64_t data,
                               unsigned size) {
  int slots[4][2] = {{0}};
  if (data != 2)
    return;
  slots[0][data] = 1; // WITNESS: nested_final_write
}

static const MemoryRegionOps nested_final_write_ops = {
    .write = nested_final_write};

typedef struct WitnessMember {
  int value;
} WitnessMember;

static void member_read(void *opaque, uint64_t addr, uint64_t data,
                        unsigned size) {
  WitnessMember slots[4] = {{0}};
  if (data != 4)
    return;
  result = slots[data].value; // WITNESS: member_read
}

static const MemoryRegionOps member_read_ops = {.write = member_read};

static void member_write(void *opaque, uint64_t addr, uint64_t data,
                         unsigned size) {
  WitnessMember slots[4] = {{0}};
  if (data != 4)
    return;
  slots[data].value = 1; // WITNESS: member_write
}

static const MemoryRegionOps member_write_ops = {.write = member_write};

typedef struct WitnessBitField {
  unsigned value : 3;
} WitnessBitField;

static void member_bitfield_read(void *opaque, uint64_t addr, uint64_t data,
                                 unsigned size) {
  WitnessBitField slots[4] = {{0}};
  if (data != 4)
    return;
  result = slots[data].value; // NOT-APPLICABLE: member_bitfield_read
}

static const MemoryRegionOps member_bitfield_read_ops = {
    .write = member_bitfield_read};

static void member_bitfield_write(void *opaque, uint64_t addr, uint64_t data,
                                  unsigned size) {
  WitnessBitField slots[4] = {{0}};
  if (data != 4)
    return;
  slots[data].value = 1; // NOT-APPLICABLE: member_bitfield_write
}

static const MemoryRegionOps member_bitfield_write_ops = {
    .write = member_bitfield_write};

static void allocation_overflow(void *opaque, uint64_t addr, uint64_t data,
                                unsigned size) {
  if (data <= ((uint64_t)-1) / 2)
    return;
  malloc(data + data); // NOT-APPLICABLE: allocation_overflow
}

static const MemoryRegionOps allocation_overflow_ops = {
    .write = allocation_overflow};

static void availability_allocation(void *opaque, uint64_t addr, uint64_t data,
                                    unsigned size) {
  g_malloc(data); // NOT-APPLICABLE: availability_allocation
}

static const MemoryRegionOps availability_allocation_ops = {
    .write = availability_allocation};

typedef struct USBDevice {
  uint8_t setup_buf[8];
  uint8_t data_buf[4096];
  int setup_len;
} USBDevice;

static void usb_setup_state(USBDevice *device) {
  int length = (device->setup_buf[7] << 8) | device->setup_buf[6];
  if (length != 4097)
    return;
  device->setup_len = length; // NOT-APPLICABLE: usb_setup_state
}

static void dma_map_unmap_contract(AddressSpace *as) {
  uint64_t mapped = 8;
  void *buffer = address_space_map(as, 0, &mapped, 0, MEMTXATTRS_UNSPECIFIED);
  if (!buffer)
    return;
  address_space_unmap(as, buffer, mapped, mapped, 0); // NOT-APPLICABLE: dma_map_unmap_contract
}

static void dma_use_after_unmap(void *opaque, uint64_t addr, uint64_t data,
                                unsigned size) {
  AddressSpace *as = opaque;
  uint64_t mapped = 8;
  unsigned char *buffer = address_space_map(as, 0, &mapped, 0, MEMTXATTRS_UNSPECIFIED);
  if (!buffer)
    return;
  if (mapped != 8) {
    address_space_unmap(as, buffer, mapped, 0, 0);
    return;
  }
  address_space_unmap(as, buffer, mapped, 0, 0);
  memcpy(&result, buffer, 1); // WITNESS: dma_use_after_unmap
}

static const MemoryRegionOps dma_use_after_unmap_ops = {
    .write = dma_use_after_unmap};

static void dma_typed_short_load(void *opaque, uint64_t addr, uint64_t data,
                                 unsigned size) {
  AddressSpace *as = opaque;
  uint64_t mapped = 4;
  unsigned char *buffer = address_space_map(as, 0, &mapped, 0, MEMTXATTRS_UNSPECIFIED);
  if (!buffer)
    return;
  if (mapped != 1) {
    address_space_unmap(as, buffer, mapped, 0, 0);
    return;
  }
  result =
      *(uint32_t *)buffer; // WITNESS: dma_typed_short_load
}

static const MemoryRegionOps dma_typed_short_load_ops = {
    .write = dma_typed_short_load};

static void dma_typed_macro_short_load(void *opaque, uint64_t addr,
                                       uint64_t data, unsigned size) {
  AddressSpace *as = opaque;
  uint64_t mapped = 4;
  unsigned char *buffer = address_space_map(as, 0, &mapped, 0, MEMTXATTRS_UNSPECIFIED);
  if (!buffer)
    return;
  if (mapped != 1) {
    address_space_unmap(as, buffer, mapped, 0, 0);
    return;
  }
  result = DMA_LOAD_U32(buffer); // WITNESS: dma_typed_macro_short_load
}

static const MemoryRegionOps dma_typed_macro_short_load_ops = {
    .write = dma_typed_macro_short_load};

static void dma_typed_macro_argument_short_load(void *opaque, uint64_t addr,
                                                uint64_t data, unsigned size) {
  AddressSpace *as = opaque;
  uint64_t mapped = 4;
  unsigned char *buffer = address_space_map(as, 0, &mapped, 0, MEMTXATTRS_UNSPECIFIED);
  if (!buffer)
    return;
  if (mapped != 1) {
    address_space_unmap(as, buffer, mapped, 0, 0);
    return;
  }
  DMA_FORWARD_U32(
      *(uint32_t *)buffer); // WITNESS: dma_typed_macro_argument_short_load
}

static const MemoryRegionOps dma_typed_macro_argument_short_load_ops = {
    .write = dma_typed_macro_argument_short_load};

static void dma_typed_assignment_macro_short_load(void *opaque, uint64_t addr,
                                                  uint64_t data,
                                                  unsigned size) {
  AddressSpace *as = opaque;
  uint64_t mapped = 4;
  unsigned char *buffer = address_space_map(as, 0, &mapped, 0, MEMTXATTRS_UNSPECIFIED);
  if (!buffer)
    return;
  if (mapped != 1) {
    address_space_unmap(as, buffer, mapped, 0, 0);
    return;
  }
  DMA_ASSIGN_U32( // WITNESS: dma_typed_assignment_macro_short_load
      *(uint32_t *)buffer);
}

static const MemoryRegionOps dma_typed_assignment_macro_short_load_ops = {
    .write = dma_typed_assignment_macro_short_load};

static void dma_typed_multiline_short_store(void *opaque, uint64_t addr,
                                            uint64_t data, unsigned size) {
  AddressSpace *as = opaque;
  uint64_t mapped = 4;
  unsigned char *buffer = address_space_map(as, 0, &mapped, 1, MEMTXATTRS_UNSPECIFIED);
  if (!buffer)
    return;
  if (mapped != 1) {
    address_space_unmap(as, buffer, mapped, 1, 0);
    return;
  }
  *(uint32_t *)buffer
      = (uint32_t)data; // WITNESS: dma_typed_multiline_short_store
}

static const MemoryRegionOps dma_typed_multiline_short_store_ops = {
    .write = dma_typed_multiline_short_store};

static void dma_null_unmap_contract(AddressSpace *as) {
  uint64_t mapped = 8;
  void *buffer = address_space_map(as, 0, &mapped, 0, MEMTXATTRS_UNSPECIFIED);
  if (!buffer)
    address_space_unmap(as, buffer, mapped, 0, 0); // NOT-APPLICABLE: dma_null_unmap_contract
}

static void initialized_output(void *opaque, uint64_t addr, uint64_t data,
                               unsigned size) {
  QEMUFile *file = opaque;
  unsigned char buffer[8];
  size_t actual = qemu_get_buffer(file, buffer, sizeof(buffer));
  if (actual != 4)
    return;
  qemu_put_buffer(file, buffer, sizeof(buffer)); // WITNESS: initialized_output
}

static const MemoryRegionOps initialized_output_ops = {
    .write = initialized_output};
