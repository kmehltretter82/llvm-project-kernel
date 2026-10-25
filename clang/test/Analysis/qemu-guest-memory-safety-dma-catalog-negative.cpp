// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu -analyzer-checker=core,alpha.qemu.GuestMemorySafety -verify %s
// expected-no-diagnostics

typedef __SIZE_TYPE__ size_t;
typedef __UINT64_TYPE__ uint64_t;
typedef uint64_t hwaddr;
typedef uint64_t dma_addr_t;

typedef struct AddressSpace AddressSpace;
typedef struct PCIDevice PCIDevice;
typedef struct MemTxAttrs {
  unsigned int unspecified : 1;
} MemTxAttrs;
typedef enum {
  DMA_DIRECTION_TO_DEVICE,
  DMA_DIRECTION_FROM_DEVICE,
} DMADirection;

void *memcpy(void *, const void *, size_t);

static unsigned char source[32];

// A globally visible same-name function with a non-catalog parameter type
// must not acquire the direct-DMA map contract.
void *address_space_map(AddressSpace *, hwaddr, hwaddr *, bool, unsigned);

void wrong_prototype_is_not_modeled(AddressSpace *as) {
  hwaddr requested = 8;
  hwaddr mapped = requested;
  unsigned char *buffer = static_cast<unsigned char *>(
      address_space_map(as, 0, &mapped, true, 0));
  if (!buffer)
    return;
  memcpy(buffer, source, requested);
}

namespace shadow {

void *dma_memory_map(AddressSpace *, dma_addr_t, dma_addr_t *, DMADirection,
                     MemTxAttrs);

void namespace_function_is_not_modeled(AddressSpace *as) {
  dma_addr_t requested = 8;
  dma_addr_t mapped = requested;
  unsigned char *buffer = static_cast<unsigned char *>(dma_memory_map(
      as, 0, &mapped, DMA_DIRECTION_TO_DEVICE, MemTxAttrs{}));
  if (!buffer)
    return;
  memcpy(buffer, source, requested);
}

} // namespace shadow

struct StaticShadow {
  static void *pci_dma_map(PCIDevice *, dma_addr_t, dma_addr_t *,
                           DMADirection);
};

void static_member_is_not_modeled(PCIDevice *dev) {
  dma_addr_t requested = 8;
  dma_addr_t mapped = requested;
  unsigned char *buffer = static_cast<unsigned char *>(StaticShadow::pci_dma_map(
      dev, 0, &mapped, DMA_DIRECTION_TO_DEVICE));
  if (!buffer)
    return;
  memcpy(buffer, source, requested);
}

void block_scope_declaration_is_not_modeled() {
  void *physical_memory_map(hwaddr, hwaddr *, bool);

  hwaddr requested = 8;
  hwaddr mapped = requested;
  unsigned char *buffer = static_cast<unsigned char *>(
      physical_memory_map(0, &mapped, false));
  if (!buffer)
    return;
  memcpy(buffer, source, requested);
}
