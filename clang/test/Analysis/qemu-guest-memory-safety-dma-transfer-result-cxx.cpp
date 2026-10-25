// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:EnableDMATransferResultDiagnostics=true \
// RUN:   -analyzer-output=text -verify-ignore-unexpected=note -verify %s

typedef __UINT32_TYPE__ uint32_t;
typedef __UINT64_TYPE__ uint64_t;
typedef uint64_t hwaddr;

typedef struct AddressSpace AddressSpace;
typedef struct MemTxAttrs {
  unsigned int unspecified : 1;
} MemTxAttrs;
typedef uint32_t MemTxResult;

#define MEMTXATTRS_UNSPECIFIED ((MemTxAttrs){0})

MemTxResult address_space_read(const AddressSpace *, hwaddr, MemTxAttrs,
                               void *, hwaddr);
MemTxResult address_space_write(const AddressSpace *, hwaddr, MemTxAttrs,
                                const void *, hwaddr);
void consume_result(MemTxResult);

void range_for_body_is_discarded(const AddressSpace *as) {
  int values[] = {0, 1};
  unsigned value = 0;
  for (int element : values)
    address_space_write(as, element, MEMTXATTRS_UNSPECIFIED, &value,
                        sizeof(value)); // expected-warning@-1 {{Level B: DMA transfer failure from 'address_space_write' is ignored}}
}

void range_for_observed_expression_remains_clean(const AddressSpace *as) {
  int values[] = {0, 1};
  unsigned value = 0;
  for (int element : values)
    consume_result(address_space_read(as, element, MEMTXATTRS_UNSPECIFIED,
                                      &value, sizeof(value)));
}
