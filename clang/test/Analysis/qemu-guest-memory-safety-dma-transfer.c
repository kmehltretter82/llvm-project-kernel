// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-output=text -verify-ignore-unexpected=note -verify %s
// RUN: %clang_analyze_cc1 -triple i386-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-output=text -verify-ignore-unexpected=note -verify %s
// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -ftrivial-auto-var-init=uninitialized -DINIT_TRACKING \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:EnableInitializedByteTracking=true \
// RUN:   -analyzer-output=text -verify-ignore-unexpected=note -verify=expected,init %s
// RUN: %clang_analyze_cc1 -triple i386-unknown-linux-gnu \
// RUN:   -ftrivial-auto-var-init=uninitialized -DINIT_TRACKING \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:EnableInitializedByteTracking=true \
// RUN:   -analyzer-output=text -verify-ignore-unexpected=note -verify=expected,init %s

typedef __UINT32_TYPE__ uint32_t;
typedef __UINT64_TYPE__ uint64_t;
typedef __SIZE_TYPE__ size_t;
typedef uint64_t hwaddr;
typedef uint64_t dma_addr_t;

typedef struct AddressSpace AddressSpace;
typedef struct QEMUFile QEMUFile;
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

size_t qemu_get_buffer(QEMUFile *, unsigned char *, size_t);

MemTxResult address_space_read(const AddressSpace *, hwaddr, MemTxAttrs,
                               void *, hwaddr);
MemTxResult address_space_rw(const AddressSpace *, hwaddr, MemTxAttrs, void *,
                             hwaddr, _Bool);
MemTxResult address_space_write(const AddressSpace *, hwaddr, MemTxAttrs,
                                const void *, hwaddr);

/* This mirrors QEMU's DMA wrapper layering.  Exact inner transfer calls,
 * including one reached through the non-catalog relaxed helper, must not
 * create a second source fact or diagnostic; the outer API owns the model. */
static inline MemTxResult dma_memory_rw_relaxed(AddressSpace *as,
                                                dma_addr_t addr, void *buf,
                                                dma_addr_t len,
                                                DMADirection direction,
                                                MemTxAttrs attrs) {
  return address_space_rw(as, addr, attrs, buf, len,
                          direction == DMA_DIRECTION_FROM_DEVICE);
}

static inline MemTxResult dma_memory_rw(AddressSpace *as, dma_addr_t addr,
                                        void *buf, dma_addr_t len,
                                        DMADirection direction,
                                        MemTxAttrs attrs) {
  return dma_memory_rw_relaxed(as, addr, buf, len, direction, attrs);
}

static inline MemTxResult dma_memory_read(AddressSpace *as, dma_addr_t addr,
                                          void *buf, dma_addr_t len,
                                          MemTxAttrs attrs) {
  return dma_memory_rw(as, addr, buf, len, DMA_DIRECTION_TO_DEVICE, attrs);
}

static inline MemTxResult dma_memory_write(AddressSpace *as, dma_addr_t addr,
                                           const void *buf, dma_addr_t len,
                                           MemTxAttrs attrs) {
  return dma_memory_rw(as, addr, (void *)buf, len,
                       DMA_DIRECTION_FROM_DEVICE, attrs);
}

unsigned address_space_read_success_taints(const AddressSpace *as) {
  unsigned index;
  unsigned slots[4] = {0};
  if (address_space_read(as, 0, MEMTXATTRS_UNSPECIFIED, &index,
                         sizeof(index)) != MEMTX_OK) // expected-note@-1 {{DMA populated guest-controlled data here}}
    return 0;
  return slots[index]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                       // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

unsigned address_space_read_failure_does_not_taint(const AddressSpace *as) {
  unsigned index = 0;
  unsigned slots[4] = {0};
  if (address_space_read(as, 0, MEMTXATTRS_UNSPECIFIED, &index,
                         sizeof(index)) == MEMTX_OK)
    return 0;
  return slots[index];
}

unsigned address_space_write_does_not_taint(const AddressSpace *as) {
  unsigned index = 0;
  unsigned slots[4] = {0};
  if (address_space_write(as, 0, MEMTXATTRS_UNSPECIFIED, &index,
                          sizeof(index)) != MEMTX_OK)
    return 0;
  return slots[index];
}

unsigned address_space_rw_read_success_taints(const AddressSpace *as) {
  unsigned index;
  unsigned slots[4] = {0};
  if (address_space_rw(as, 0, MEMTXATTRS_UNSPECIFIED, &index, sizeof(index),
                       0) != MEMTX_OK) // expected-note@-1 {{DMA populated guest-controlled data here}}
    return 0;
  return slots[index]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                       // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

unsigned address_space_rw_write_does_not_taint(const AddressSpace *as) {
  unsigned index = 0;
  unsigned slots[4] = {0};
  if (address_space_rw(as, 0, MEMTXATTRS_UNSPECIFIED, &index, sizeof(index),
                       1) != MEMTX_OK)
    return 0;
  return slots[index];
}

unsigned address_space_rw_dynamic_direction(const AddressSpace *as,
                                            _Bool is_write) {
  unsigned index;
  unsigned slots[4] = {0};
  if (address_space_rw(as, 0, MEMTXATTRS_UNSPECIFIED, &index, sizeof(index),
                       is_write) != MEMTX_OK) // expected-note@-1 {{DMA populated guest-controlled data here}}
    return 0;
  if (is_write)
    return 0;
  return slots[index]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                       // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

unsigned nested_dma_memory_read_success_taints(AddressSpace *as) {
  unsigned index;
  unsigned slots[4] = {0};
  if (dma_memory_read(as, 0, &index, sizeof(index),
                      MEMTXATTRS_UNSPECIFIED) != MEMTX_OK) // expected-note@-1 {{DMA populated guest-controlled data here}}
    return 0;
  return slots[index]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                       // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

unsigned dma_memory_read_failure_does_not_taint(AddressSpace *as) {
  unsigned index = 0;
  unsigned slots[4] = {0};
  if (dma_memory_read(as, 0, &index, sizeof(index),
                      MEMTXATTRS_UNSPECIFIED) == MEMTX_OK)
    return 0;
  return slots[index];
}

unsigned dma_memory_write_does_not_taint(AddressSpace *as) {
  unsigned index = 0;
  unsigned slots[4] = {0};
  if (dma_memory_write(as, 0, &index, sizeof(index),
                       MEMTXATTRS_UNSPECIFIED) != MEMTX_OK)
    return 0;
  return slots[index];
}

unsigned dma_memory_rw_to_device_taints(AddressSpace *as) {
  unsigned index;
  unsigned slots[4] = {0};
  if (dma_memory_rw(as, 0, &index, sizeof(index), DMA_DIRECTION_TO_DEVICE,
                    MEMTXATTRS_UNSPECIFIED) != MEMTX_OK) // expected-note@-1 {{DMA populated guest-controlled data here}}
    return 0;
  return slots[index]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                       // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

unsigned dma_memory_rw_from_device_does_not_taint(AddressSpace *as) {
  unsigned index = 0;
  unsigned slots[4] = {0};
  if (dma_memory_rw(as, 0, &index, sizeof(index), DMA_DIRECTION_FROM_DEVICE,
                    MEMTXATTRS_UNSPECIFIED) != MEMTX_OK)
    return 0;
  return slots[index];
}

unsigned dma_memory_rw_invalid_direction_follows_read_arm(AddressSpace *as) {
  unsigned index;
  unsigned slots[4] = {0};
  if (dma_memory_rw(as, 0, &index, sizeof(index), (DMADirection)7,
                    MEMTXATTRS_UNSPECIFIED) != MEMTX_OK) // expected-note@-1 {{DMA populated guest-controlled data here}}
    return 0;
  return slots[index]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                       // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

unsigned dma_memory_rw_dynamic_direction(AddressSpace *as,
                                         DMADirection direction) {
  unsigned index;
  unsigned slots[4] = {0};
  if (dma_memory_rw(as, 0, &index, sizeof(index), direction,
                    MEMTXATTRS_UNSPECIFIED) != MEMTX_OK) // expected-note@-1 {{DMA populated guest-controlled data here}}
    return 0;
  if (direction == DMA_DIRECTION_FROM_DEVICE)
    return 0;
  return slots[index]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                       // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

#ifdef INIT_TRACKING
void dma_memory_write_checks_initialized_prefix(QEMUFile *input,
                                                AddressSpace *as) {
  unsigned char buffer[8];
  if (qemu_get_buffer(input, buffer, sizeof(buffer)) != 4)
    return;
  (void)dma_memory_write(as, 0, buffer, sizeof(buffer),
                         MEMTXATTRS_UNSPECIFIED); // init-warning@-1 {{Level A: host-read length exceeds the initialized byte prefix}}
}

void address_space_write_checks_initialized_prefix(QEMUFile *input,
                                                   const AddressSpace *as) {
  unsigned char buffer[8];
  if (qemu_get_buffer(input, buffer, sizeof(buffer)) != 4)
    return;
  (void)address_space_write(as, 0, MEMTXATTRS_UNSPECIFIED, buffer,
                            sizeof(buffer)); // init-warning@-1 {{Level A: host-read length exceeds the initialized byte prefix}}
}
#endif
