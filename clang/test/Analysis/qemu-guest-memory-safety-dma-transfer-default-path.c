// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,debug.ExprInspection,alpha.qemu.GuestMemorySafety \
// RUN:   -verify %s
// RUN: %clang_analyze_cc1 -triple i386-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,debug.ExprInspection,alpha.qemu.GuestMemorySafety \
// RUN:   -verify %s

typedef __UINT32_TYPE__ uint32_t;
typedef __UINT64_TYPE__ uint64_t;
typedef uint64_t hwaddr;

typedef struct AddressSpace AddressSpace;
typedef struct MemTxAttrs {
  unsigned int unspecified : 1;
} MemTxAttrs;
typedef uint32_t MemTxResult;

#define MEMTX_OK ((MemTxResult)0)
#define MEMTXATTRS_UNSPECIFIED ((MemTxAttrs){0})

MemTxResult address_space_read(const AddressSpace *, hwaddr, MemTxAttrs,
                               void *, hwaddr);
MemTxResult address_space_write(const AddressSpace *, hwaddr, MemTxAttrs,
                                const void *, hwaddr);
void clang_analyzer_numTimesReached(void);

void discarded_host_read_does_not_fork(const AddressSpace *as) {
  unsigned value = 0;
  address_space_write(as, 0, MEMTXATTRS_UNSPECIFIED, &value, sizeof(value));
  clang_analyzer_numTimesReached(); // expected-warning {{1}}
}

void observed_host_read_keeps_result_states(const AddressSpace *as) {
  unsigned value = 0;
  MemTxResult result = address_space_write(
      as, 0, MEMTXATTRS_UNSPECIFIED, &value, sizeof(value));
  if (result == MEMTX_OK)
    ++value;
  clang_analyzer_numTimesReached(); // expected-warning {{2}}
}

void discarded_host_write_keeps_success_effects(const AddressSpace *as) {
  unsigned value;
  address_space_read(as, 0, MEMTXATTRS_UNSPECIFIED, &value, sizeof(value));
  clang_analyzer_numTimesReached(); // expected-warning {{2}}
}
