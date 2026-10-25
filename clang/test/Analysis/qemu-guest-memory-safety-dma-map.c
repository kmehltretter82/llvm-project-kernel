// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu -Wno-array-bounds -analyzer-checker=core,alpha.qemu.GuestMemorySafety -verify=expected,LP64 %s
// RUN: %clang_analyze_cc1 -triple i386-unknown-linux-gnu -Wno-array-bounds -analyzer-checker=core,alpha.qemu.GuestMemorySafety -verify=expected,ILP32 %s

typedef __SIZE_TYPE__ size_t;
typedef __UINT32_TYPE__ uint32_t;
typedef __UINT64_TYPE__ uint64_t;
typedef uint64_t hwaddr;
typedef uint64_t dma_addr_t;

typedef struct AddressSpace AddressSpace;
typedef struct PCIDevice PCIDevice;
typedef struct MemTxAttrs {
  unsigned int unspecified : 1;
} MemTxAttrs;
#define MEMTXATTRS_UNSPECIFIED ((MemTxAttrs){0})
typedef enum {
  DMA_DIRECTION_TO_DEVICE,
  DMA_DIRECTION_FROM_DEVICE,
} DMADirection;

void *memcpy(void *, const void *, size_t);
void *memset(void *, int, size_t);
void consume_u32(uint32_t);

void *address_space_map(AddressSpace *, hwaddr, hwaddr *, _Bool, MemTxAttrs);
void address_space_unmap(AddressSpace *, void *, hwaddr, _Bool, hwaddr);
void *dma_memory_map(AddressSpace *, dma_addr_t, dma_addr_t *, DMADirection,
                     MemTxAttrs);
void dma_memory_unmap(AddressSpace *, void *, dma_addr_t, DMADirection,
                      dma_addr_t);
void *pci_dma_map(PCIDevice *, dma_addr_t, dma_addr_t *, DMADirection);
void pci_dma_unmap(PCIDevice *, void *, dma_addr_t, DMADirection, dma_addr_t);
void *physical_memory_map(hwaddr, hwaddr *, _Bool);
void physical_memory_unmap(void *, hwaddr, _Bool, hwaddr);

#define DMA_LOAD_U32(pointer) (*(uint32_t *)(pointer))
#define DMA_FORWARD_U32(value) consume_u32(value)

static unsigned char source[32];
static unsigned char destination[32];

typedef struct {
  uint32_t first;
  uint32_t second;
} DMATypedRecord;

void address_space_requested_length_bad(AddressSpace *as) {
  hwaddr requested = 8;
  hwaddr mapped = requested;
  unsigned char *buffer = address_space_map(as, 0, &mapped, 1, MEMTXATTRS_UNSPECIFIED);
  if (!buffer)
    return;
  memcpy(buffer, source, requested); // expected-warning {{direct DMA mapped-buffer access size may exceed the host object extent}}
  address_space_unmap(as, buffer, mapped, 1, requested);
}

void address_space_returned_length_good(AddressSpace *as) {
  hwaddr mapped = 8;
  unsigned char *buffer = address_space_map(as, 0, &mapped, 1, MEMTXATTRS_UNSPECIFIED);
  if (!buffer)
    return;
  memcpy(buffer, source, mapped);
  address_space_unmap(as, buffer, mapped, 1, mapped);
}

void address_space_guarded_length_good(AddressSpace *as) {
  hwaddr requested = 8;
  hwaddr mapped = requested;
  unsigned char *buffer = address_space_map(as, 0, &mapped, 1, MEMTXATTRS_UNSPECIFIED);
  if (!buffer)
    return;
  if (mapped < requested) {
    address_space_unmap(as, buffer, mapped, 1, 0);
    return;
  }
  memcpy(buffer, source, requested);
  address_space_unmap(as, buffer, mapped, 1, requested);
}

uint32_t address_space_typed_load_short_bad(AddressSpace *as) {
  hwaddr mapped = 4;
  unsigned char *buffer = address_space_map(as, 0, &mapped, 0, MEMTXATTRS_UNSPECIFIED);
  if (!buffer)
    return 0;
  if (mapped != 1) {
    address_space_unmap(as, buffer, mapped, 0, 0);
    return 0;
  }
  uint32_t value = *(uint32_t *)buffer; // expected-warning {{direct DMA mapped-buffer typed access end exceeds the host object extent}}
  address_space_unmap(as, buffer, mapped, 0, 0);
  return value;
}

uint32_t address_space_typed_macro_load_short_bad(AddressSpace *as) {
  hwaddr mapped = 4;
  unsigned char *buffer = address_space_map(as, 0, &mapped, 0, MEMTXATTRS_UNSPECIFIED);
  if (!buffer)
    return 0;
  if (mapped != 1) {
    address_space_unmap(as, buffer, mapped, 0, 0);
    return 0;
  }
  uint32_t value = DMA_LOAD_U32(buffer); // expected-warning {{direct DMA mapped-buffer typed access end exceeds the host object extent}}
  address_space_unmap(as, buffer, mapped, 0, 0);
  return value;
}

void address_space_typed_macro_argument_load_short_bad(AddressSpace *as) {
  hwaddr mapped = 4;
  unsigned char *buffer = address_space_map(as, 0, &mapped, 0, MEMTXATTRS_UNSPECIFIED);
  if (!buffer)
    return;
  if (mapped != 1) {
    address_space_unmap(as, buffer, mapped, 0, 0);
    return;
  }
  DMA_FORWARD_U32( // expected-warning {{direct DMA mapped-buffer typed access end exceeds the host object extent}}
      *(uint32_t *)buffer);
  address_space_unmap(as, buffer, mapped, 0, 0);
}

void address_space_typed_store_short_bad(AddressSpace *as, uint32_t value) {
  hwaddr mapped = 4;
  unsigned char *buffer = address_space_map(as, 0, &mapped, 1, MEMTXATTRS_UNSPECIFIED);
  if (!buffer)
    return;
  if (mapped != 1) {
    address_space_unmap(as, buffer, mapped, 1, 0);
    return;
  }
  *(uint32_t *)buffer = value; // expected-warning {{direct DMA mapped-buffer typed access end exceeds the host object extent}}
  address_space_unmap(as, buffer, mapped, 1, 0);
}

uint32_t address_space_typed_index_bad(AddressSpace *as) {
  hwaddr mapped = 8;
  unsigned char *buffer = address_space_map(as, 0, &mapped, 0, MEMTXATTRS_UNSPECIFIED);
  if (!buffer)
    return 0;
  if (mapped != 4) {
    address_space_unmap(as, buffer, mapped, 0, 0);
    return 0;
  }
  uint32_t value = ((uint32_t *)buffer)[1]; // expected-warning {{direct DMA mapped-buffer typed access end exceeds the host object extent}}
  address_space_unmap(as, buffer, mapped, 0, 0);
  return value;
}

uint32_t address_space_typed_size_t_overflow_scope(AddressSpace *as) {
  hwaddr mapped = sizeof(uint32_t);
  unsigned char *buffer = address_space_map(as, 0, &mapped, 0, MEMTXATTRS_UNSPECIFIED);
  if (!buffer)
    return 0;
  if (mapped != sizeof(uint32_t)) {
    address_space_unmap(as, buffer, mapped, 0, 0);
    return 0;
  }
  uint32_t value = ((uint32_t *)buffer)[0x40000000ULL]; // LP64-warning {{direct DMA mapped-buffer typed access end exceeds the host object extent}}
  address_space_unmap(as, buffer, mapped, 0, 0);
  return value;
}

uint32_t address_space_typed_field_bad(AddressSpace *as) {
  hwaddr mapped = sizeof(DMATypedRecord);
  unsigned char *buffer = address_space_map(as, 0, &mapped, 0, MEMTXATTRS_UNSPECIFIED);
  if (!buffer)
    return 0;
  if (mapped != sizeof(uint32_t)) {
    address_space_unmap(as, buffer, mapped, 0, 0);
    return 0;
  }
  uint32_t value = ((DMATypedRecord *)buffer)->second; // expected-warning {{direct DMA mapped-buffer typed access end exceeds the host object extent}}
  address_space_unmap(as, buffer, mapped, 0, 0);
  return value;
}

uint32_t address_space_typed_exact_end_good(AddressSpace *as) {
  hwaddr mapped = sizeof(uint32_t);
  unsigned char *buffer = address_space_map(as, 0, &mapped, 0, MEMTXATTRS_UNSPECIFIED);
  if (!buffer)
    return 0;
  if (mapped != sizeof(uint32_t)) {
    address_space_unmap(as, buffer, mapped, 0, 0);
    return 0;
  }
  uint32_t value = *(uint32_t *)buffer;
  address_space_unmap(as, buffer, mapped, 0, 0);
  return value;
}

uint32_t address_space_typed_guarded_length_good(AddressSpace *as) {
  hwaddr mapped = sizeof(uint32_t);
  unsigned char *buffer = address_space_map(as, 0, &mapped, 0, MEMTXATTRS_UNSPECIFIED);
  if (!buffer)
    return 0;
  if (mapped < sizeof(uint32_t)) {
    address_space_unmap(as, buffer, mapped, 0, 0);
    return 0;
  }
  uint32_t value = *(uint32_t *)buffer;
  address_space_unmap(as, buffer, mapped, 0, 0);
  return value;
}

uint32_t address_space_typed_volatile_load_short_bad(AddressSpace *as) {
  hwaddr mapped = sizeof(uint32_t);
  unsigned char *buffer = address_space_map(as, 0, &mapped, 0, MEMTXATTRS_UNSPECIFIED);
  if (!buffer)
    return 0;
  if (mapped != 1) {
    address_space_unmap(as, buffer, mapped, 0, 0);
    return 0;
  }
  uint32_t value = *(volatile uint32_t *)buffer; // expected-warning {{direct DMA mapped-buffer typed access end exceeds the host object extent}}
  address_space_unmap(as, buffer, mapped, 0, 0);
  return value;
}

void address_space_typed_volatile_store_short_bad(AddressSpace *as,
                                                  uint32_t value) {
  hwaddr mapped = sizeof(uint32_t);
  unsigned char *buffer = address_space_map(as, 0, &mapped, 1, MEMTXATTRS_UNSPECIFIED);
  if (!buffer)
    return;
  if (mapped != 1) {
    address_space_unmap(as, buffer, mapped, 1, 0);
    return;
  }
  *(volatile uint32_t *)buffer = value; // expected-warning {{direct DMA mapped-buffer typed access end exceeds the host object extent}}
  address_space_unmap(as, buffer, mapped, 1, 0);
}

uint32_t address_space_typed_pointer_alias_short_bad(AddressSpace *as) {
  hwaddr mapped = sizeof(uint32_t);
  unsigned char *buffer = address_space_map(as, 0, &mapped, 0, MEMTXATTRS_UNSPECIFIED);
  if (!buffer)
    return 0;
  uint32_t *alias = (uint32_t *)buffer;
  if (mapped != 1) {
    address_space_unmap(as, buffer, mapped, 0, 0);
    return 0;
  }
  uint32_t value = *alias; // expected-warning {{direct DMA mapped-buffer typed access end exceeds the host object extent}}
  address_space_unmap(as, buffer, mapped, 0, 0);
  return value;
}

uint32_t ordinary_non_dma_typed_good(uint32_t *pointer) {
  return *pointer;
}

void address_space_typed_aggregate_scope(AddressSpace *as,
                                         DMATypedRecord *destination,
                                         DMATypedRecord value) {
  hwaddr mapped = sizeof(DMATypedRecord);
  unsigned char *buffer = address_space_map(as, 0, &mapped, 0, MEMTXATTRS_UNSPECIFIED);
  if (!buffer)
    return;
  if (mapped != sizeof(uint32_t)) {
    address_space_unmap(as, buffer, mapped, 0, 0);
    return;
  }
  *destination = *(DMATypedRecord *)buffer;
  *(DMATypedRecord *)buffer = value;
  address_space_unmap(as, buffer, mapped, 0, 0);
}

void address_space_typed_address_only_good(AddressSpace *as) {
  hwaddr mapped = sizeof(uint32_t);
  unsigned char *buffer = address_space_map(as, 0, &mapped, 0, MEMTXATTRS_UNSPECIFIED);
  if (!buffer)
    return;
  uint32_t *address = &((uint32_t *)buffer)[1];
  (void)address;
  address_space_unmap(as, buffer, mapped, 0, 0);
}

uint32_t address_space_typed_load_after_unmap_bad(AddressSpace *as) {
  hwaddr mapped = sizeof(uint32_t);
  unsigned char *buffer = address_space_map(as, 0, &mapped, 0, MEMTXATTRS_UNSPECIFIED);
  if (!buffer)
    return 0;
  address_space_unmap(as, buffer, mapped, 0, 0); // expected-note {{DMA mapping unmapped here}}
  return *(uint32_t *)buffer; // expected-warning {{direct DMA mapped buffer is accessed after it was unmapped}}
}

void address_space_typed_store_after_unmap_bad(AddressSpace *as,
                                               uint32_t value) {
  hwaddr mapped = sizeof(DMATypedRecord);
  unsigned char *buffer = address_space_map(as, 0, &mapped, 1, MEMTXATTRS_UNSPECIFIED);
  if (!buffer)
    return;
  DMATypedRecord *record = (DMATypedRecord *)buffer;
  address_space_unmap(as, buffer, mapped, 1, 0); // expected-note {{DMA mapping unmapped here}}
  record->second = value; // expected-warning {{direct DMA mapped buffer is accessed after it was unmapped}}
}

uint32_t address_space_typed_symbolic_after_unmap_bad(AddressSpace *as,
                                                      size_t index) {
  hwaddr mapped = sizeof(DMATypedRecord);
  unsigned char *buffer = address_space_map(as, 0, &mapped, 0, MEMTXATTRS_UNSPECIFIED);
  if (!buffer)
    return 0;
  address_space_unmap(as, buffer, mapped, 0, 0); // expected-note {{DMA mapping unmapped here}}
  return ((uint32_t *)buffer)[index]; // expected-warning {{direct DMA mapped buffer is accessed after it was unmapped}}
}

uint32_t dma_memory_typed_load_short_bad(AddressSpace *as) {
  dma_addr_t mapped = sizeof(uint32_t);
  unsigned char *buffer =
      dma_memory_map(as, 0, &mapped, DMA_DIRECTION_TO_DEVICE, MEMTXATTRS_UNSPECIFIED);
  if (!buffer)
    return 0;
  if (mapped != 1) {
    dma_memory_unmap(as, buffer, mapped, DMA_DIRECTION_TO_DEVICE, 0);
    return 0;
  }
  uint32_t value = *(uint32_t *)buffer; // expected-warning {{direct DMA mapped-buffer typed access end exceeds the host object extent}}
  dma_memory_unmap(as, buffer, mapped, DMA_DIRECTION_TO_DEVICE, 0);
  return value;
}

void pci_dma_typed_store_short_bad(PCIDevice *dev, uint32_t value) {
  dma_addr_t mapped = sizeof(uint32_t);
  unsigned char *buffer =
      pci_dma_map(dev, 0, &mapped, DMA_DIRECTION_FROM_DEVICE);
  if (!buffer)
    return;
  if (mapped != 1) {
    pci_dma_unmap(dev, buffer, mapped, DMA_DIRECTION_FROM_DEVICE, 0);
    return;
  }
  *(uint32_t *)buffer = value; // expected-warning {{direct DMA mapped-buffer typed access end exceeds the host object extent}}
  pci_dma_unmap(dev, buffer, mapped, DMA_DIRECTION_FROM_DEVICE, 0);
}

uint32_t physical_memory_typed_load_short_bad(void) {
  hwaddr mapped = sizeof(uint32_t);
  unsigned char *buffer = physical_memory_map(0, &mapped, 0);
  if (!buffer)
    return 0;
  if (mapped != 1) {
    physical_memory_unmap(buffer, mapped, 0, 0);
    return 0;
  }
  uint32_t value = *(uint32_t *)buffer; // expected-warning {{direct DMA mapped-buffer typed access end exceeds the host object extent}}
  physical_memory_unmap(buffer, mapped, 0, 0);
  return value;
}

void address_space_source_bad(AddressSpace *as) {
  hwaddr requested = 8;
  hwaddr mapped = requested;
  unsigned char *buffer = address_space_map(as, 0, &mapped, 0, MEMTXATTRS_UNSPECIFIED);
  if (!buffer)
    return;
  memcpy(destination, buffer, requested); // expected-warning {{direct DMA mapped-buffer access size may exceed the host object extent}}
  address_space_unmap(as, buffer, mapped, 0, requested);
}

void address_space_offset_bad(AddressSpace *as) {
  hwaddr requested = 16;
  hwaddr mapped = requested;
  unsigned char *buffer = address_space_map(as, 0, &mapped, 1, MEMTXATTRS_UNSPECIFIED);
  if (!buffer)
    return;
  if (mapped != 12) {
    address_space_unmap(as, buffer, mapped, 1, 0);
    return;
  }
  memcpy(buffer + 4, source, 12); // expected-warning {{direct DMA mapped-buffer offset plus access size exceeds the host object extent}}
  address_space_unmap(as, buffer, mapped, 1, 12);
}

void dma_memory_requested_length_bad(AddressSpace *as) {
  dma_addr_t requested = 8;
  dma_addr_t mapped = requested;
  unsigned char *buffer =
      dma_memory_map(as, 0, &mapped, DMA_DIRECTION_FROM_DEVICE, MEMTXATTRS_UNSPECIFIED);
  if (!buffer)
    return;
  memcpy(buffer, source, requested); // expected-warning {{direct DMA mapped-buffer access size may exceed the host object extent}}
  dma_memory_unmap(as, buffer, mapped, DMA_DIRECTION_FROM_DEVICE, requested);
}

void pci_dma_requested_length_bad(PCIDevice *dev) {
  dma_addr_t requested = 8;
  dma_addr_t mapped = requested;
  unsigned char *buffer =
      pci_dma_map(dev, 0, &mapped, DMA_DIRECTION_FROM_DEVICE);
  if (!buffer)
    return;
  memcpy(buffer, source, requested); // expected-warning {{direct DMA mapped-buffer access size may exceed the host object extent}}
  pci_dma_unmap(dev, buffer, mapped, DMA_DIRECTION_FROM_DEVICE, requested);
}

void physical_memory_requested_length_bad(void) {
  hwaddr requested = 8;
  hwaddr mapped = requested;
  unsigned char *buffer = physical_memory_map(0, &mapped, 1);
  if (!buffer)
    return;
  memcpy(buffer, source, requested); // expected-warning {{direct DMA mapped-buffer access size may exceed the host object extent}}
  physical_memory_unmap(buffer, mapped, 1, requested);
}

void unmap_ends_extent_tracking(AddressSpace *as) {
  hwaddr requested = 8;
  hwaddr mapped = requested;
  unsigned char *buffer = address_space_map(as, 0, &mapped, 1, MEMTXATTRS_UNSPECIFIED);
  if (!buffer)
    return;
  address_space_unmap(as, buffer, mapped, 1, 0); // expected-note {{DMA mapping unmapped here}}
  memcpy(buffer, source, requested); // expected-warning {{direct DMA mapped buffer is accessed after it was unmapped}}
}

void address_space_read_after_unmap_bad(AddressSpace *as) {
  hwaddr mapped = 8;
  unsigned char *buffer = address_space_map(as, 0, &mapped, 0, MEMTXATTRS_UNSPECIFIED);
  if (!buffer)
    return;
  address_space_unmap(as, buffer, mapped, 0, 0); // expected-note {{DMA mapping unmapped here}}
  memcpy(destination, buffer, 1); // expected-warning {{direct DMA mapped buffer is accessed after it was unmapped}}
}

void address_space_write_after_unmap_bad(AddressSpace *as) {
  hwaddr mapped = 8;
  unsigned char *buffer = address_space_map(as, 0, &mapped, 1, MEMTXATTRS_UNSPECIFIED);
  if (!buffer)
    return;
  address_space_unmap(as, buffer, mapped, 1, 0); // expected-note {{DMA mapping unmapped here}}
  memset(buffer, 0, 1); // expected-warning {{direct DMA mapped buffer is accessed after it was unmapped}}
}

void address_space_alias_after_unmap_bad(AddressSpace *as) {
  hwaddr mapped = 8;
  unsigned char *buffer = address_space_map(as, 0, &mapped, 0, MEMTXATTRS_UNSPECIFIED);
  if (!buffer)
    return;
  unsigned char *alias = buffer + 1;
  address_space_unmap(as, buffer, mapped, 0, 0); // expected-note {{DMA mapping unmapped here}}
  memcpy(destination, alias, 1); // expected-warning {{direct DMA mapped buffer is accessed after it was unmapped}}
}

void destination_lifetime_split_stops_only_invalid_path(AddressSpace *as,
                                                        size_t length) {
  hwaddr destination_mapped = 8;
  hwaddr source_mapped = 8;
  unsigned char *mapped_destination =
      address_space_map(as, 0, &destination_mapped, 1, MEMTXATTRS_UNSPECIFIED);
  if (!mapped_destination)
    return;
  unsigned char *mapped_source =
      address_space_map(as, 8, &source_mapped, 0, MEMTXATTRS_UNSPECIFIED);
  if (!mapped_source) {
    address_space_unmap(as, mapped_destination, destination_mapped, 1, 0);
    return;
  }
  address_space_unmap(as, mapped_destination, destination_mapped, 1, 0); // expected-note {{DMA mapping unmapped here}}
  memcpy(mapped_destination, mapped_source, length); // expected-warning {{direct DMA mapped buffer is accessed after it was unmapped}}
  /* Only the zero-length successor may continue past the lifetime error. */
  if (length > 0)
    memset(mapped_destination, 0, 1);
  address_space_unmap(as, mapped_source, source_mapped, 0, 0);
}

void destination_spatial_report_preserves_source_lifetime(AddressSpace *as) {
  hwaddr destination_mapped = 8;
  hwaddr source_mapped = 8;
  unsigned char *mapped_destination =
      address_space_map(as, 0, &destination_mapped, 1, MEMTXATTRS_UNSPECIFIED);
  if (!mapped_destination)
    return;
  unsigned char *mapped_source =
      address_space_map(as, 8, &source_mapped, 0, MEMTXATTRS_UNSPECIFIED);
  if (!mapped_source) {
    address_space_unmap(as, mapped_destination, destination_mapped, 1, 0);
    return;
  }
  address_space_unmap(as, mapped_source, source_mapped, 0, 0); // expected-note {{DMA mapping unmapped here}}
  memcpy(mapped_destination, mapped_source, 8); // expected-warning {{direct DMA mapped-buffer access size may exceed the host object extent}}
                                                 // expected-warning@-1 {{direct DMA mapped buffer is accessed after it was unmapped}}
}

void address_space_double_unmap_bad(AddressSpace *as) {
  hwaddr mapped = 8;
  unsigned char *buffer = address_space_map(as, 0, &mapped, 0, MEMTXATTRS_UNSPECIFIED);
  if (!buffer)
    return;
  unsigned char *alias = buffer;
  address_space_unmap(as, alias, mapped, 0, 0);
  address_space_unmap(as, buffer, mapped, 0, 0); // expected-warning {{direct DMA mapping is unmapped more than once}}
}

void address_space_zero_length_after_unmap_good(AddressSpace *as) {
  hwaddr mapped = 8;
  unsigned char *buffer = address_space_map(as, 0, &mapped, 0, MEMTXATTRS_UNSPECIFIED);
  if (!buffer)
    return;
  address_space_unmap(as, buffer, mapped, 0, 0);
  memcpy(destination, buffer, 0);
}

void address_space_remap_after_unmap_good(AddressSpace *as) {
  hwaddr mapped = 8;
  unsigned char *buffer = address_space_map(as, 0, &mapped, 0, MEMTXATTRS_UNSPECIFIED);
  if (!buffer)
    return;
  address_space_unmap(as, buffer, mapped, 0, 0);
  mapped = 8;
  buffer = address_space_map(as, 0, &mapped, 0, MEMTXATTRS_UNSPECIFIED);
  if (!buffer)
    return;
  if (mapped < 1) {
    address_space_unmap(as, buffer, mapped, 0, 0);
    return;
  }
  memcpy(destination, buffer, 1);
  address_space_unmap(as, buffer, mapped, 0, 1);
}

void address_space_loop_remap_after_unmap_good(AddressSpace *as) {
  for (int i = 0; i != 2; ++i) {
    hwaddr mapped = 8;
    unsigned char *buffer = address_space_map(as, 0, &mapped, 0, MEMTXATTRS_UNSPECIFIED);
    if (!buffer)
      return;
    if (mapped < 1) {
      address_space_unmap(as, buffer, mapped, 0, 0);
      return;
    }
    memcpy(destination, buffer, 1);
    address_space_unmap(as, buffer, mapped, 0, 1);
  }
}

void address_space_unmap_reversed_order_bad(AddressSpace *as) {
  hwaddr mapped = 8;
  unsigned char *buffer = address_space_map(as, 0, &mapped, 0, MEMTXATTRS_UNSPECIFIED);
  if (!buffer)
    return;
  memcpy(destination, buffer, mapped);
  address_space_unmap(as, buffer, mapped, mapped, 0); // expected-warning {{direct DMA unmap arguments match the reversed argument order}} expected-note {{DMA mapping unmapped here}}
  /* A reported unmap becomes a retired-mapping tombstone, not a stale map. */
  memcpy(buffer, source, 9); // expected-warning {{direct DMA mapped buffer is accessed after it was unmapped}}
}

void address_space_unmap_length_bad(AddressSpace *as) {
  hwaddr mapped = 8;
  unsigned char *buffer = address_space_map(as, 0, &mapped, 1, MEMTXATTRS_UNSPECIFIED);
  if (!buffer)
    return;
  if (mapped != 8)
    return;
  address_space_unmap(as, buffer, 4, 1, 4); // expected-warning {{direct DMA unmap length differs from the returned map length}}
}

void address_space_unmap_access_length_bad(AddressSpace *as) {
  hwaddr mapped = 8;
  unsigned char *buffer = address_space_map(as, 0, &mapped, 1, MEMTXATTRS_UNSPECIFIED);
  if (!buffer)
    return;
  if (mapped != 8)
    return;
  address_space_unmap(as, buffer, mapped, 1, 9); // expected-warning {{direct DMA unmap access length exceeds the returned map length}}
}

void address_space_unmap_direction_bad(AddressSpace *as) {
  hwaddr mapped = 8;
  unsigned char *buffer = address_space_map(as, 0, &mapped, 0, MEMTXATTRS_UNSPECIFIED);
  if (!buffer)
    return;
  address_space_unmap(as, buffer, mapped, 1, 1); // expected-warning {{direct DMA unmap direction differs from the map direction}}
}

void address_space_zero_access_direction_change_good(AddressSpace *as,
                                                     _Bool direction) {
  hwaddr mapped = 8;
  unsigned char *buffer = address_space_map(as, 0, &mapped, direction, MEMTXATTRS_UNSPECIFIED);
  if (!buffer)
    return;
  if (mapped != 8)
    return;
  address_space_unmap(as, buffer, mapped, 0, 0);
}

void address_space_partial_access_good(AddressSpace *as) {
  hwaddr mapped = 8;
  unsigned char *buffer = address_space_map(as, 0, &mapped, 1, MEMTXATTRS_UNSPECIFIED);
  if (!buffer)
    return;
  if (mapped != 8)
    return;
  memcpy(buffer, source, 4);
  address_space_unmap(as, buffer, mapped, 1, 4);
}

void dma_memory_unmap_direction_bad(AddressSpace *as) {
  dma_addr_t mapped = 8;
  unsigned char *buffer =
      dma_memory_map(as, 0, &mapped, DMA_DIRECTION_TO_DEVICE, MEMTXATTRS_UNSPECIFIED);
  if (!buffer)
    return;
  dma_memory_unmap(as, buffer, mapped, DMA_DIRECTION_FROM_DEVICE, 1); // expected-warning {{direct DMA unmap direction differs from the map direction}}
}

void physical_memory_unmap_direction_bad(void) {
  hwaddr mapped = 8;
  unsigned char *buffer = physical_memory_map(0, &mapped, 0);
  if (!buffer)
    return;
  physical_memory_unmap(buffer, mapped, 1, 1); // expected-warning {{direct DMA unmap direction differs from the map direction}}
}

void physical_memory_bool_access_length_good(_Bool dirty) {
  hwaddr mapped = 1;
  unsigned char *buffer = physical_memory_map(0, &mapped, 1);
  if (!buffer)
    return;
  if (mapped != 1)
    return;
  physical_memory_unmap(buffer, mapped, 1, dirty);
}

void address_space_null_mapping_unmap_bad(AddressSpace *as) {
  hwaddr mapped = 8;
  unsigned char *buffer = address_space_map(as, 0, &mapped, 1, MEMTXATTRS_UNSPECIFIED);
  if (!buffer)
    address_space_unmap(as, buffer, mapped, 1, 0); // expected-warning {{direct DMA unmap is called with a null mapping}}
}

void address_space_nonzero_extent_excludes_null_good(AddressSpace *as) {
  hwaddr mapped = 8;
  unsigned char *buffer = address_space_map(as, 0, &mapped, 1, MEMTXATTRS_UNSPECIFIED);
  if (mapped == 8 && !buffer)
    address_space_unmap(as, buffer, mapped, 1, 0);
}

void address_space_null_implies_zero_extent_good(AddressSpace *as) {
  hwaddr mapped = 8;
  unsigned char *buffer = address_space_map(as, 0, &mapped, 1, MEMTXATTRS_UNSPECIFIED);
  if (!buffer && mapped != 0)
    address_space_unmap(as, buffer, mapped, 1, 0);
}

void dma_memory_null_mapping_unmap_bad(AddressSpace *as) {
  dma_addr_t mapped = 8;
  unsigned char *buffer =
      dma_memory_map(as, 0, &mapped, DMA_DIRECTION_FROM_DEVICE, MEMTXATTRS_UNSPECIFIED);
  if (!buffer)
    dma_memory_unmap(as, buffer, mapped, DMA_DIRECTION_FROM_DEVICE, 0); // expected-warning {{direct DMA unmap is called with a null mapping}}
}

void pci_dma_null_mapping_unmap_bad(PCIDevice *dev) {
  dma_addr_t mapped = 8;
  unsigned char *buffer =
      pci_dma_map(dev, 0, &mapped, DMA_DIRECTION_FROM_DEVICE);
  if (!buffer)
    pci_dma_unmap(dev, buffer, mapped, DMA_DIRECTION_FROM_DEVICE, 0); // expected-warning {{direct DMA unmap is called with a null mapping}}
}

void physical_memory_null_mapping_unmap_bad(void) {
  hwaddr mapped = 8;
  unsigned char *buffer = physical_memory_map(0, &mapped, 0);
  if (!buffer)
    physical_memory_unmap(buffer, mapped, 0, 0); // expected-warning {{direct DMA unmap is called with a null mapping}}
}

void maybe_null_untracked_mapping_is_not_enough(AddressSpace *as,
                                                 void *buffer) {
  address_space_unmap(as, buffer, 8, 0, 0);
}

void *not_dma_memory_map(AddressSpace *, dma_addr_t, dma_addr_t *, unsigned,
                         unsigned);

void similarly_named_function_is_ignored(AddressSpace *as) {
  dma_addr_t mapped = 8;
  unsigned char *buffer = not_dma_memory_map(as, 0, &mapped, 1, 0);
  if (!buffer)
    return;
  memcpy(buffer, source, 8);
}
