// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:EnableDMATransferResultDiagnostics=true \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:SelectiveSummaryManifest=%S/../../../../validation/v3-selective-ctu-summary-pci-dma-stage1/current-d7314928-stage1-v2.json \
// RUN:   -verify %s 2>&1 | FileCheck %s --check-prefix=COUNTERS-X86_64
// RUN: %clang_analyze_cc1 -triple i386-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:EnableDMATransferResultDiagnostics=true \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:SelectiveSummaryManifest=%S/../../../../validation/v3-selective-ctu-summary-pci-dma-stage1/current-d7314928-stage1-v2.json \
// RUN:   -verify %s 2>&1 | FileCheck %s --check-prefix=COUNTERS-I386
// expected-no-diagnostics

typedef unsigned long long dma_addr_t;
typedef unsigned int MemTxResult;
typedef struct AddressSpace AddressSpace;
typedef struct DeviceState DeviceState;
typedef struct ScatterGatherEntry ScatterGatherEntry;
typedef struct QEMUSGList QEMUSGList;
typedef struct MemTxAttrs {
  unsigned int unspecified : 1;
} MemTxAttrs;
struct QEMUSGList {
  ScatterGatherEntry *sg;
  int nsg;
  int nalloc;
  dma_addr_t size;
  DeviceState *dev;
  AddressSpace *as;
};

/* Exact prototype and name, but not the manifest-bound header declaration. */
MemTxResult dma_buf_read(void *, dma_addr_t, dma_addr_t *, QEMUSGList *,
                         MemTxAttrs);

#line 304 "include/system/dma.h"
/* Exact header coordinate and name, but an incompatible prototype. */
MemTxResult dma_buf_write(void *, unsigned int);

#line 1 "selective-summary-negative.c"
void declaration_header_mismatch(void *buffer, dma_addr_t length,
                                 QEMUSGList *sg, MemTxAttrs attrs) {
  dma_buf_read(buffer, length, 0, sg, attrs);
}

void prototype_mismatch(void *buffer) {
  dma_buf_write(buffer, 1);
}

// COUNTERS-X86_64: QEMU_GMS_SELECTIVE_SUMMARY_V2 loaded=3 matched=0 consumed=0 unsupported=0
// COUNTERS-I386: QEMU_GMS_SELECTIVE_SUMMARY_V2 loaded=3 matched=0 consumed=0 unsupported=0
