// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu -analyzer-checker=core,alpha.qemu.GuestMemorySafety -verify %s
// RUN: %clang_analyze_cc1 -triple i386-unknown-linux-gnu -analyzer-checker=core,alpha.qemu.GuestMemorySafety -verify %s

typedef __UINT32_TYPE__ uint32_t;
typedef __UINT64_TYPE__ uint64_t;
typedef uint64_t hwaddr;
typedef uint64_t dma_addr_t;

typedef struct AddressSpace AddressSpace;
typedef struct PCIDevice {
  AddressSpace *address_space;
} PCIDevice;
typedef struct MemTxAttrs {
  unsigned int unspecified : 1;
} MemTxAttrs;
typedef enum {
  DMA_DIRECTION_TO_DEVICE,
  DMA_DIRECTION_FROM_DEVICE,
} DMADirection;

void *pci_dma_map(PCIDevice *, dma_addr_t, dma_addr_t *, DMADirection);

void address_space_unmap(AddressSpace *as, void *buffer, hwaddr len,
                         _Bool is_write, hwaddr access_len) {}

void dma_memory_unmap(AddressSpace *as, void *buffer, dma_addr_t len,
                      DMADirection direction, dma_addr_t access_len) {
  address_space_unmap(as, buffer, len,
                      direction == DMA_DIRECTION_FROM_DEVICE, access_len);
}

void pci_dma_unmap(PCIDevice *device, void *buffer, dma_addr_t len,
                   DMADirection direction, dma_addr_t access_len) {
  dma_memory_unmap(device->address_space, buffer, len, direction, access_len);
}

void nested_unmap_once_good(PCIDevice *device) {
  dma_addr_t mapped = 8;
  unsigned char *buffer =
      pci_dma_map(device, 0, &mapped, DMA_DIRECTION_TO_DEVICE);
  if (!buffer)
    return;
  pci_dma_unmap(device, buffer, mapped, DMA_DIRECTION_TO_DEVICE, mapped);
}

uint32_t nested_unmap_retires_at_outer_post(PCIDevice *device) {
  dma_addr_t mapped = 8;
  unsigned char *buffer =
      pci_dma_map(device, 0, &mapped, DMA_DIRECTION_TO_DEVICE);
  if (!buffer)
    return 0;
  pci_dma_unmap( // expected-note {{DMA mapping unmapped here}}
      device, buffer, mapped, DMA_DIRECTION_TO_DEVICE, mapped);
  return *(uint32_t *)buffer; // expected-warning {{direct DMA mapped buffer is accessed after it was unmapped}}
}

void nested_unmap_wrong_outer_owner(PCIDevice *mapped_device,
                                    PCIDevice *unmap_device) {
  if (mapped_device == unmap_device)
    return;
  dma_addr_t mapped = 8;
  unsigned char *buffer =
      pci_dma_map(mapped_device, 0, &mapped, DMA_DIRECTION_TO_DEVICE);
  if (!buffer)
    return;
  pci_dma_unmap( // expected-warning {{direct DMA unmap owner differs from the map owner}}
      unmap_device, buffer, mapped, DMA_DIRECTION_TO_DEVICE, mapped);
}
