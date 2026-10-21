// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.qemu.GuestMemorySafety -verify %s

typedef __SIZE_TYPE__ size_t;
typedef __UINT64_TYPE__ uint64_t;
typedef uint64_t hwaddr;
typedef uint64_t dma_addr_t;

typedef struct AddressSpace AddressSpace;
typedef struct PCIDevice PCIDevice;

void *memcpy(void *, const void *, size_t);

void *address_space_map(AddressSpace *, hwaddr, hwaddr *, _Bool, unsigned);
void address_space_unmap(AddressSpace *, void *, hwaddr, _Bool, hwaddr);
void *dma_memory_map(AddressSpace *, dma_addr_t, dma_addr_t *, unsigned,
                     unsigned);
void dma_memory_unmap(AddressSpace *, void *, dma_addr_t, unsigned,
                      dma_addr_t);
void *pci_dma_map(PCIDevice *, dma_addr_t, dma_addr_t *, unsigned);
void pci_dma_unmap(PCIDevice *, void *, dma_addr_t, unsigned, dma_addr_t);
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
  unsigned char *buffer = dma_memory_map(as, 0, &mapped, 1, 0);
  if (!buffer)
    return;
  memcpy(buffer, source, requested); // expected-warning {{direct DMA mapped-buffer access size may exceed the host object extent}}
  dma_memory_unmap(as, buffer, mapped, 1, requested);
}

void pci_dma_requested_length_bad(PCIDevice *dev) {
  dma_addr_t requested = 8;
  dma_addr_t mapped = requested;
  unsigned char *buffer = pci_dma_map(dev, 0, &mapped, 1);
  if (!buffer)
    return;
  memcpy(buffer, source, requested); // expected-warning {{direct DMA mapped-buffer access size may exceed the host object extent}}
  pci_dma_unmap(dev, buffer, mapped, 1, requested);
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
  address_space_unmap(as, buffer, mapped, 1, 0);
  /* A use-after-unmap is for a lifetime checker, not this extent model. */
  memcpy(buffer, source, requested);
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
