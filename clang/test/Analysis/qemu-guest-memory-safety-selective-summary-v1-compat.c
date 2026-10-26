// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:EnableDMATransferResultDiagnostics=true \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:SelectiveSummaryManifest=%S/../../../../validation/v3-selective-ctu-summary/current-d7314928.json \
// RUN:   -analyzer-output=text -verify-ignore-unexpected=note -verify=expected %s 2>&1 | FileCheck %s --check-prefix=COUNTERS-X86_64
// RUN: %clang_analyze_cc1 -triple i386-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:EnableDMATransferResultDiagnostics=true \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:SelectiveSummaryManifest=%S/../../../../validation/v3-selective-ctu-summary/current-d7314928.json \
// RUN:   -analyzer-output=text -verify-ignore-unexpected=note -verify=expected %s 2>&1 | FileCheck %s --check-prefix=COUNTERS-I386

typedef unsigned long long dma_addr_t;
typedef unsigned int MemTxResult;
typedef struct AddressSpace AddressSpace;
typedef struct DeviceState DeviceState;
typedef struct ScatterGatherEntry ScatterGatherEntry;
typedef struct QEMUSGList QEMUSGList;
typedef struct MemTxAttrs {
  unsigned int unspecified : 1;
} MemTxAttrs;

#line 1 "include/system/dma.h"
struct QEMUSGList {
  ScatterGatherEntry *sg;
  int nsg;
  int nalloc;
  dma_addr_t size;
  DeviceState *dev;
  AddressSpace *as;
};

#line 302
MemTxResult dma_buf_read(void *, dma_addr_t, dma_addr_t *, QEMUSGList *,
                         MemTxAttrs);

#line 1 "selective-summary-v1-compat.c"
void legacy_manifest_still_loads(void *buffer, dma_addr_t length,
                                 QEMUSGList *sg, MemTxAttrs attrs) {
  dma_buf_read(buffer, length, 0, sg, attrs);
  // expected-warning@-1 {{Level B: DMA transfer failure from 'dma_buf_read' is ignored}}
}

// COUNTERS-X86_64: QEMU_GMS_SELECTIVE_SUMMARY_V1 loaded=2 matched=1 consumed=1 unsupported=1
// COUNTERS-I386: QEMU_GMS_SELECTIVE_SUMMARY_V1 loaded=2 matched=1 consumed=1 unsupported=1
