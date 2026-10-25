// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -ftrivial-auto-var-init=uninitialized \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:EnableInitializedByteTracking=true \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:EnableDMATransferResultDiagnostics=true \
// RUN:   -verify %s
// RUN: %clang_analyze_cc1 -triple i386-unknown-linux-gnu \
// RUN:   -ftrivial-auto-var-init=uninitialized \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:EnableInitializedByteTracking=true \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:EnableDMATransferResultDiagnostics=true \
// RUN:   -verify %s
// expected-no-diagnostics

typedef __UINT32_TYPE__ uint32_t;
typedef __UINT64_TYPE__ uint64_t;
typedef uint64_t hwaddr;
typedef uint64_t dma_addr_t;

typedef struct AddressSpace AddressSpace;
typedef struct MemTxAttrs {
  unsigned int unspecified : 1;
} MemTxAttrs;
typedef uint32_t MemTxResult;
typedef enum {
  DMA_DIRECTION_TO_DEVICE,
  DMA_DIRECTION_FROM_DEVICE,
} DMADirection;

#define MEMTX_OK ((MemTxResult)0)
#define MEMTXATTRS_UNSPECIFIED ((MemTxAttrs){0})

/* Every declaration deliberately differs from its generated catalog
 * prototype.  Same-name lookalikes must remain ordinary unknown calls. */
MemTxResult address_space_read(const AddressSpace *, hwaddr, MemTxAttrs,
                               void *, unsigned);
MemTxResult address_space_rw(const AddressSpace *, hwaddr, MemTxAttrs, void *,
                             hwaddr, unsigned);
MemTxResult address_space_write(const AddressSpace *, hwaddr, MemTxAttrs,
                                const void *, unsigned);
MemTxResult dma_memory_read(AddressSpace *, dma_addr_t, void *, unsigned,
                            MemTxAttrs);
MemTxResult dma_memory_rw(AddressSpace *, dma_addr_t, void *, dma_addr_t,
                          unsigned, MemTxAttrs);
MemTxResult dma_memory_write(AddressSpace *, dma_addr_t, const void *,
                             unsigned, MemTxAttrs);

static unsigned use_as_index(unsigned index) {
  unsigned slots[4] = {0};
  return slots[index];
}

unsigned wrong_address_space_read_is_not_a_source(const AddressSpace *as) {
  unsigned index = 0;
  if (address_space_read(as, 0, MEMTXATTRS_UNSPECIFIED, &index,
                         sizeof(index)) != MEMTX_OK)
    return 0;
  return use_as_index(index);
}

unsigned wrong_address_space_rw_is_not_a_source(const AddressSpace *as) {
  unsigned index = 0;
  if (address_space_rw(as, 0, MEMTXATTRS_UNSPECIFIED, &index, sizeof(index),
                       0) != MEMTX_OK)
    return 0;
  return use_as_index(index);
}

void wrong_address_space_write_is_not_a_sink(const AddressSpace *as) {
  unsigned char buffer[8];
  buffer[0] = 1;
  (void)address_space_write(as, 0, MEMTXATTRS_UNSPECIFIED, buffer,
                            sizeof(buffer));
}

unsigned wrong_dma_memory_read_is_not_a_source(AddressSpace *as) {
  unsigned index = 0;
  if (dma_memory_read(as, 0, &index, sizeof(index),
                      MEMTXATTRS_UNSPECIFIED) != MEMTX_OK)
    return 0;
  return use_as_index(index);
}

unsigned wrong_dma_memory_rw_is_not_a_source(AddressSpace *as) {
  unsigned index = 0;
  if (dma_memory_rw(as, 0, &index, sizeof(index),
                    DMA_DIRECTION_TO_DEVICE,
                    MEMTXATTRS_UNSPECIFIED) != MEMTX_OK)
    return 0;
  return use_as_index(index);
}

void wrong_dma_memory_write_is_not_a_sink(AddressSpace *as) {
  unsigned char buffer[8];
  buffer[0] = 1;
  (void)dma_memory_write(as, 0, buffer, sizeof(buffer),
                         MEMTXATTRS_UNSPECIFIED);
}

void wrong_same_name_bare_results_are_not_diagnosed(AddressSpace *as) {
  unsigned buffer = 0;
  address_space_read(as, 0, MEMTXATTRS_UNSPECIFIED, &buffer, sizeof(buffer));
  dma_memory_write(as, 0, &buffer, sizeof(buffer),
                   MEMTXATTRS_UNSPECIFIED);
}
