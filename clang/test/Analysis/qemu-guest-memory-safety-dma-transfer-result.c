// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:EnableDMATransferResultDiagnostics=true \
// RUN:   -analyzer-output=text -verify-ignore-unexpected=note -verify %s
// RUN: %clang_analyze_cc1 -triple i386-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:EnableDMATransferResultDiagnostics=true \
// RUN:   -analyzer-output=text -verify-ignore-unexpected=note -verify %s

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

MemTxResult address_space_read(const AddressSpace *, hwaddr, MemTxAttrs,
                               void *, hwaddr);
MemTxResult address_space_rw(const AddressSpace *, hwaddr, MemTxAttrs, void *,
                             hwaddr, _Bool);
MemTxResult address_space_write(const AddressSpace *, hwaddr, MemTxAttrs,
                                const void *, hwaddr);

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

void bare_address_space_read(const AddressSpace *as) {
  unsigned value;
  address_space_read(as, 0, MEMTXATTRS_UNSPECIFIED, &value,
                     sizeof(value)); // expected-warning@-1 {{Level B: DMA transfer failure from 'address_space_read' is ignored}}
}

void bare_address_space_write(const AddressSpace *as) {
  unsigned value = 0;
  address_space_write(as, 0, MEMTXATTRS_UNSPECIFIED, &value,
                      sizeof(value)); // expected-warning@-1 {{Level B: DMA transfer failure from 'address_space_write' is ignored}}
}

void bare_dynamic_address_space_rw(const AddressSpace *as, _Bool is_write) {
  unsigned value = 0;
  address_space_rw(as, 0, MEMTXATTRS_UNSPECIFIED, &value, sizeof(value),
                   is_write); // expected-warning@-1 {{Level B: DMA transfer failure from 'address_space_rw' is ignored}}
}

void explicit_void_discard_is_deliberate(const AddressSpace *as) {
  unsigned value = 0;
  (void)address_space_write(as, 0, MEMTXATTRS_UNSPECIFIED, &value,
                            sizeof(value));
}

void inline_check_is_observed(const AddressSpace *as) {
  unsigned value;
  if (address_space_read(as, 0, MEMTXATTRS_UNSPECIFIED, &value,
                         sizeof(value)) != MEMTX_OK)
    return;
}

void assigned_then_checked_is_observed(const AddressSpace *as) {
  unsigned value;
  MemTxResult result = address_space_read(
      as, 0, MEMTXATTRS_UNSPECIFIED, &value, sizeof(value));
  if (result != MEMTX_OK)
    return;
}

void assigned_but_unchecked_is_later_scope(const AddressSpace *as) {
  unsigned value = 0;
  MemTxResult result = address_space_write(
      as, 0, MEMTXATTRS_UNSPECIFIED, &value, sizeof(value));
  (void)result;
}

MemTxResult return_propagation_is_observed(const AddressSpace *as) {
  unsigned value = 0;
  return address_space_write(as, 0, MEMTXATTRS_UNSPECIFIED, &value,
                             sizeof(value));
}

void consume_result(MemTxResult);

void outer_call_argument_is_observed(const AddressSpace *as) {
  unsigned value = 0;
  consume_result(address_space_write(as, 0, MEMTXATTRS_UNSPECIFIED, &value,
                                     sizeof(value)));
}

void comma_lhs_is_discarded(const AddressSpace *as) {
  unsigned value = 0;
  (address_space_write(as, 0, MEMTXATTRS_UNSPECIFIED, &value,
                       sizeof(value)), // expected-warning@-1 {{Level B: DMA transfer failure from 'address_space_write' is ignored}}
   ++value);
}

MemTxResult comma_rhs_is_returned(const AddressSpace *as) {
  unsigned value = 0;
  return (++value, address_space_write(as, 0, MEMTXATTRS_UNSPECIFIED, &value,
                                       sizeof(value)));
}

void parenthesized_discard(const AddressSpace *as) {
  unsigned value = 0;
  (address_space_write(as, 0, MEMTXATTRS_UNSPECIFIED, &value,
                       sizeof(value))); // expected-warning@-1 {{Level B: DMA transfer failure from 'address_space_write' is ignored}}
}

void nonvoid_cast_discard(const AddressSpace *as) {
  unsigned value = 0;
  (unsigned)address_space_write(
      as, 0, MEMTXATTRS_UNSPECIFIED, &value,
      sizeof(value)); // expected-warning@-2 {{expression result unused}}
                      // expected-warning@-3 {{Level B: DMA transfer failure from 'address_space_write' is ignored}}
}

void nested_wrapper_reports_only_outer_call(AddressSpace *as) {
  unsigned value;
  dma_memory_read(as, 0, &value, sizeof(value),
                  MEMTXATTRS_UNSPECIFIED); // expected-warning@-1 {{Level B: DMA transfer failure from 'dma_memory_read' is ignored}}
}

void unbraced_if_bodies_are_discarded(const AddressSpace *as, int select) {
  unsigned value = 0;
  if (select)
    address_space_write(as, 0, MEMTXATTRS_UNSPECIFIED, &value,
                        sizeof(value)); // expected-warning@-1 {{Level B: DMA transfer failure from 'address_space_write' is ignored}}
  else
    dma_memory_write((AddressSpace *)as, 0, &value, sizeof(value),
                     MEMTXATTRS_UNSPECIFIED); // expected-warning@-1 {{Level B: DMA transfer failure from 'dma_memory_write' is ignored}}
}

void unbraced_if_observed_expressions_remain_clean(const AddressSpace *as,
                                                    int select) {
  unsigned value = 0;
  MemTxResult result = MEMTX_OK;
  if (address_space_read(as, 0, MEMTXATTRS_UNSPECIFIED, &value,
                         sizeof(value)) != MEMTX_OK)
    return;
  if (select)
    result = address_space_write(as, 0, MEMTXATTRS_UNSPECIFIED, &value,
                                 sizeof(value));
  else
    consume_result(address_space_write(as, 0, MEMTXATTRS_UNSPECIFIED, &value,
                                       sizeof(value)));
  consume_result(result);
}

void switch_case_bodies_are_discarded(AddressSpace *as, int select) {
  unsigned value = 0;
  switch (select) {
  case 0:
    address_space_write(as, 0, MEMTXATTRS_UNSPECIFIED, &value,
                        sizeof(value)); // expected-warning@-1 {{Level B: DMA transfer failure from 'address_space_write' is ignored}}
    break;
  case 1:
  case 2:
    dma_memory_read(as, 0, &value, sizeof(value),
                    MEMTXATTRS_UNSPECIFIED); // expected-warning@-1 {{Level B: DMA transfer failure from 'dma_memory_read' is ignored}}
    break;
  default:
    dma_memory_write(as, 0, &value, sizeof(value),
                     MEMTXATTRS_UNSPECIFIED); // expected-warning@-1 {{Level B: DMA transfer failure from 'dma_memory_write' is ignored}}
    break;
  }
}

void switch_case_observed_expressions_remain_clean(const AddressSpace *as,
                                                    int select) {
  unsigned value = 0;
  switch (select) {
  case 0:
    consume_result(address_space_write(as, 0, MEMTXATTRS_UNSPECIFIED, &value,
                                       sizeof(value)));
    break;
  default:
    if (address_space_read(as, 0, MEMTXATTRS_UNSPECIFIED, &value,
                           sizeof(value)) != MEMTX_OK)
      return;
  }
}

void label_body_is_discarded(AddressSpace *as, int retry) {
  unsigned value = 0;
again:
  address_space_write(as, 0, MEMTXATTRS_UNSPECIFIED, &value,
                      sizeof(value)); // expected-warning@-1 {{Level B: DMA transfer failure from 'address_space_write' is ignored}}
  if (retry-- > 0)
    goto again;
}

void label_observed_expression_remains_clean(const AddressSpace *as) {
  unsigned value = 0;
observed:
  consume_result(address_space_write(as, 0, MEMTXATTRS_UNSPECIFIED, &value,
                                     sizeof(value)));
  if (value)
    goto observed;
}

void unbraced_loop_bodies_are_discarded(AddressSpace *as, int count) {
  unsigned value = 0;
  while (count-- > 0)
    address_space_write(as, 0, MEMTXATTRS_UNSPECIFIED, &value,
                        sizeof(value)); // expected-warning@-1 {{Level B: DMA transfer failure from 'address_space_write' is ignored}}
  do
    dma_memory_write(as, 0, &value, sizeof(value),
                     MEMTXATTRS_UNSPECIFIED); // expected-warning@-1 {{Level B: DMA transfer failure from 'dma_memory_write' is ignored}}
  while (count-- > 0);
  for (; count-- > 0;)
    dma_memory_read(as, 0, &value, sizeof(value),
                    MEMTXATTRS_UNSPECIFIED); // expected-warning@-1 {{Level B: DMA transfer failure from 'dma_memory_read' is ignored}}
}

void loop_observed_expressions_remain_clean(const AddressSpace *as,
                                            int count) {
  unsigned value = 0;
  while (address_space_read(as, 0, MEMTXATTRS_UNSPECIFIED, &value,
                            sizeof(value)) == MEMTX_OK)
    break;
  do {
    --count;
  } while (address_space_write(as, 0, MEMTXATTRS_UNSPECIFIED, &value,
                               sizeof(value)) == MEMTX_OK);
  for (; count > 0;
       consume_result(address_space_write(as, 0, MEMTXATTRS_UNSPECIFIED,
                                          &value, sizeof(value))))
    --count;
}
