// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.qemu.GuestMemorySafety -verify %s

typedef __SIZE_TYPE__ size_t;
typedef __UINT64_TYPE__ uint64_t;
typedef uint64_t hwaddr;
typedef uint64_t dma_addr_t;

typedef struct AddressSpace AddressSpace;
typedef struct PCIDevice PCIDevice;
typedef enum {
  DMA_DIRECTION_TO_DEVICE,
  DMA_DIRECTION_FROM_DEVICE,
} DMADirection;

void *memcpy(void *, const void *, size_t);
void *memset(void *, int, size_t);

void *address_space_map(AddressSpace *, hwaddr, hwaddr *, _Bool, unsigned);
void address_space_unmap(AddressSpace *, void *, hwaddr, _Bool, hwaddr);
void *dma_memory_map(AddressSpace *, dma_addr_t, dma_addr_t *, DMADirection,
                     unsigned);
void dma_memory_unmap(AddressSpace *, void *, dma_addr_t, DMADirection,
                      dma_addr_t);
void *pci_dma_map(PCIDevice *, dma_addr_t, dma_addr_t *, DMADirection);
void pci_dma_unmap(PCIDevice *, void *, dma_addr_t, DMADirection, dma_addr_t);
void *physical_memory_map(hwaddr, hwaddr *, _Bool);
void physical_memory_unmap(void *, hwaddr, _Bool, hwaddr);

static unsigned char source[32];
static unsigned char destination[32];

void address_space_requested_length_bad(AddressSpace *as) {
  hwaddr requested = 8;
  hwaddr mapped = requested;
  unsigned char *buffer = address_space_map(as, 0, &mapped, 1, 0);
  if (!buffer)
    return;
  memcpy(buffer, source, requested); // expected-warning {{direct DMA mapped-buffer access size may exceed the host object extent}}
  address_space_unmap(as, buffer, mapped, 1, requested);
}

void address_space_returned_length_good(AddressSpace *as) {
  hwaddr mapped = 8;
  unsigned char *buffer = address_space_map(as, 0, &mapped, 1, 0);
  if (!buffer)
    return;
  memcpy(buffer, source, mapped);
  address_space_unmap(as, buffer, mapped, 1, mapped);
}

void address_space_guarded_length_good(AddressSpace *as) {
  hwaddr requested = 8;
  hwaddr mapped = requested;
  unsigned char *buffer = address_space_map(as, 0, &mapped, 1, 0);
  if (!buffer)
    return;
  if (mapped < requested) {
    address_space_unmap(as, buffer, mapped, 1, 0);
    return;
  }
  memcpy(buffer, source, requested);
  address_space_unmap(as, buffer, mapped, 1, requested);
}

void address_space_source_bad(AddressSpace *as) {
  hwaddr requested = 8;
  hwaddr mapped = requested;
  unsigned char *buffer = address_space_map(as, 0, &mapped, 0, 0);
  if (!buffer)
    return;
  memcpy(destination, buffer, requested); // expected-warning {{direct DMA mapped-buffer access size may exceed the host object extent}}
  address_space_unmap(as, buffer, mapped, 0, requested);
}

void address_space_offset_bad(AddressSpace *as) {
  hwaddr requested = 16;
  hwaddr mapped = requested;
  unsigned char *buffer = address_space_map(as, 0, &mapped, 1, 0);
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
      dma_memory_map(as, 0, &mapped, DMA_DIRECTION_FROM_DEVICE, 0);
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
  unsigned char *buffer = address_space_map(as, 0, &mapped, 1, 0);
  if (!buffer)
    return;
  address_space_unmap(as, buffer, mapped, 1, 0); // expected-note {{DMA mapping unmapped here}}
  memcpy(buffer, source, requested); // expected-warning {{direct DMA mapped buffer is accessed after it was unmapped}}
}

void address_space_read_after_unmap_bad(AddressSpace *as) {
  hwaddr mapped = 8;
  unsigned char *buffer = address_space_map(as, 0, &mapped, 0, 0);
  if (!buffer)
    return;
  address_space_unmap(as, buffer, mapped, 0, 0); // expected-note {{DMA mapping unmapped here}}
  memcpy(destination, buffer, 1); // expected-warning {{direct DMA mapped buffer is accessed after it was unmapped}}
}

void address_space_write_after_unmap_bad(AddressSpace *as) {
  hwaddr mapped = 8;
  unsigned char *buffer = address_space_map(as, 0, &mapped, 1, 0);
  if (!buffer)
    return;
  address_space_unmap(as, buffer, mapped, 1, 0); // expected-note {{DMA mapping unmapped here}}
  memset(buffer, 0, 1); // expected-warning {{direct DMA mapped buffer is accessed after it was unmapped}}
}

void address_space_alias_after_unmap_bad(AddressSpace *as) {
  hwaddr mapped = 8;
  unsigned char *buffer = address_space_map(as, 0, &mapped, 0, 0);
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
      address_space_map(as, 0, &destination_mapped, 1, 0);
  if (!mapped_destination)
    return;
  unsigned char *mapped_source =
      address_space_map(as, 8, &source_mapped, 0, 0);
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
      address_space_map(as, 0, &destination_mapped, 1, 0);
  if (!mapped_destination)
    return;
  unsigned char *mapped_source =
      address_space_map(as, 8, &source_mapped, 0, 0);
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
  unsigned char *buffer = address_space_map(as, 0, &mapped, 0, 0);
  if (!buffer)
    return;
  unsigned char *alias = buffer;
  address_space_unmap(as, alias, mapped, 0, 0);
  address_space_unmap(as, buffer, mapped, 0, 0); // expected-warning {{direct DMA mapping is unmapped more than once}}
}

void address_space_zero_length_after_unmap_good(AddressSpace *as) {
  hwaddr mapped = 8;
  unsigned char *buffer = address_space_map(as, 0, &mapped, 0, 0);
  if (!buffer)
    return;
  address_space_unmap(as, buffer, mapped, 0, 0);
  memcpy(destination, buffer, 0);
}

void address_space_remap_after_unmap_good(AddressSpace *as) {
  hwaddr mapped = 8;
  unsigned char *buffer = address_space_map(as, 0, &mapped, 0, 0);
  if (!buffer)
    return;
  address_space_unmap(as, buffer, mapped, 0, 0);
  mapped = 8;
  buffer = address_space_map(as, 0, &mapped, 0, 0);
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
    unsigned char *buffer = address_space_map(as, 0, &mapped, 0, 0);
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
  unsigned char *buffer = address_space_map(as, 0, &mapped, 0, 0);
  if (!buffer)
    return;
  memcpy(destination, buffer, mapped);
  address_space_unmap(as, buffer, mapped, mapped, 0); // expected-warning {{direct DMA unmap arguments match the reversed argument order}} expected-note {{DMA mapping unmapped here}}
  /* A reported unmap becomes a retired-mapping tombstone, not a stale map. */
  memcpy(buffer, source, 9); // expected-warning {{direct DMA mapped buffer is accessed after it was unmapped}}
}

void address_space_unmap_length_bad(AddressSpace *as) {
  hwaddr mapped = 8;
  unsigned char *buffer = address_space_map(as, 0, &mapped, 1, 0);
  if (!buffer)
    return;
  if (mapped != 8)
    return;
  address_space_unmap(as, buffer, 4, 1, 4); // expected-warning {{direct DMA unmap length differs from the returned map length}}
}

void address_space_unmap_access_length_bad(AddressSpace *as) {
  hwaddr mapped = 8;
  unsigned char *buffer = address_space_map(as, 0, &mapped, 1, 0);
  if (!buffer)
    return;
  if (mapped != 8)
    return;
  address_space_unmap(as, buffer, mapped, 1, 9); // expected-warning {{direct DMA unmap access length exceeds the returned map length}}
}

void address_space_unmap_direction_bad(AddressSpace *as) {
  hwaddr mapped = 8;
  unsigned char *buffer = address_space_map(as, 0, &mapped, 0, 0);
  if (!buffer)
    return;
  address_space_unmap(as, buffer, mapped, 1, 1); // expected-warning {{direct DMA unmap direction differs from the map direction}}
}

void address_space_zero_access_direction_change_good(AddressSpace *as,
                                                     _Bool direction) {
  hwaddr mapped = 8;
  unsigned char *buffer = address_space_map(as, 0, &mapped, direction, 0);
  if (!buffer)
    return;
  if (mapped != 8)
    return;
  address_space_unmap(as, buffer, mapped, 0, 0);
}

void address_space_partial_access_good(AddressSpace *as) {
  hwaddr mapped = 8;
  unsigned char *buffer = address_space_map(as, 0, &mapped, 1, 0);
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
      dma_memory_map(as, 0, &mapped, DMA_DIRECTION_TO_DEVICE, 0);
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
  unsigned char *buffer = address_space_map(as, 0, &mapped, 1, 0);
  if (!buffer)
    address_space_unmap(as, buffer, mapped, 1, 0); // expected-warning {{direct DMA unmap is called with a null mapping}}
}

void address_space_nonzero_extent_excludes_null_good(AddressSpace *as) {
  hwaddr mapped = 8;
  unsigned char *buffer = address_space_map(as, 0, &mapped, 1, 0);
  if (mapped == 8 && !buffer)
    address_space_unmap(as, buffer, mapped, 1, 0);
}

void address_space_null_implies_zero_extent_good(AddressSpace *as) {
  hwaddr mapped = 8;
  unsigned char *buffer = address_space_map(as, 0, &mapped, 1, 0);
  if (!buffer && mapped != 0)
    address_space_unmap(as, buffer, mapped, 1, 0);
}

void dma_memory_null_mapping_unmap_bad(AddressSpace *as) {
  dma_addr_t mapped = 8;
  unsigned char *buffer =
      dma_memory_map(as, 0, &mapped, DMA_DIRECTION_FROM_DEVICE, 0);
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
