// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-output=text -verify-ignore-unexpected=note -verify=default %s 2>&1 | FileCheck %s --check-prefix=DEFAULT-X86_64 --allow-empty
// RUN: %clang_analyze_cc1 -triple i386-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-output=text -verify-ignore-unexpected=note -verify=default %s 2>&1 | FileCheck %s --check-prefix=DEFAULT-I386 --allow-empty
// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:EnableDMATransferResultDiagnostics=true \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:SelectiveSummaryManifest=%S/../../../../validation/v3-selective-ctu-summary/current-d7314928.json \
// RUN:   -analyzer-output=text -verify-ignore-unexpected=note -verify=summary %s 2>&1 | FileCheck %s --check-prefix=COUNTERS-X86_64
// RUN: %clang_analyze_cc1 -triple i386-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:EnableDMATransferResultDiagnostics=true \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:SelectiveSummaryManifest=%S/../../../../validation/v3-selective-ctu-summary/current-d7314928.json \
// RUN:   -analyzer-output=text -verify-ignore-unexpected=note -verify=summary %s 2>&1 | FileCheck %s --check-prefix=COUNTERS-I386
// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:EnableDMATransferResultDiagnostics=true \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:SelectiveSummaryManifest=%S/../../../../validation/v3-selective-ctu-summary/current-d7314928.json \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:EmitStructuredWitness=true \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:QEMUSourceRoot=/qemu-test \
// RUN:   -DQEMU_SELECTIVE_SUMMARY_WITNESS \
// RUN:   -analyzer-output=text %s 2>&1 | \
// RUN:   %python %S/Inputs/qemu-gms-selective-summary-witness-validate.py \
// RUN:   qemu-guest-memory-safety-selective-summary.c
// The i386 runs test target-independent checker matching and result behavior;
// the sealed producer manifest itself is x86_64 evidence.
// default-no-diagnostics
// DEFAULT-X86_64-NOT: QEMU_GMS_SELECTIVE_SUMMARY_V1
// DEFAULT-I386-NOT: QEMU_GMS_SELECTIVE_SUMMARY_V1

#line 1 "include/system/dma.h"
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

#line 302
MemTxResult dma_buf_read(void *, dma_addr_t, dma_addr_t *, QEMUSGList *,
                         MemTxAttrs);
#line 304
MemTxResult dma_buf_write(void *, dma_addr_t, dma_addr_t *, QEMUSGList *,
                          MemTxAttrs);

#ifdef QEMU_SELECTIVE_SUMMARY_WITNESS
#line 1 "/qemu-test/qemu-guest-memory-safety-selective-summary.c"
#else
#line 1 "selective-summary-calls.c"
#endif
void ahci_pair(void *buffer, dma_addr_t length, QEMUSGList *sg,
               MemTxAttrs attrs) {
  dma_buf_read(buffer, length, 0, sg, attrs);
  // summary-warning@-1 {{Level B: DMA transfer failure from 'dma_buf_read' is ignored}}
  dma_buf_write(buffer, length, 0, sg, attrs);
  // summary-warning@-1 {{Level B: DMA transfer failure from 'dma_buf_write' is ignored}}
}

void nvme_pair(void *buffer, dma_addr_t length, dma_addr_t *residual,
               QEMUSGList *sg, MemTxAttrs attrs) {
  dma_buf_read(buffer, length, residual, sg, attrs);
  // summary-warning@-1 {{Level B: DMA transfer failure from 'dma_buf_read' is ignored}}
  dma_buf_write(buffer, length, residual, sg, attrs);
  // summary-warning@-1 {{Level B: DMA transfer failure from 'dma_buf_write' is ignored}}
}

void scsi_pair(void *buffer, dma_addr_t length, dma_addr_t *residual,
               QEMUSGList *sg, MemTxAttrs attrs) {
  dma_buf_read(buffer, length, residual, sg, attrs);
  // summary-warning@-1 {{Level B: DMA transfer failure from 'dma_buf_read' is ignored}}
  dma_buf_write(buffer, length, residual, sg, attrs);
  // summary-warning@-1 {{Level B: DMA transfer failure from 'dma_buf_write' is ignored}}
}

int ufs_checks_result(void *buffer, dma_addr_t length, QEMUSGList *sg,
                      MemTxAttrs attrs) {
  if (dma_buf_read(buffer, length, 0, sg, attrs) != 0)
    return -1;
  return 0;
}

// COUNTERS-X86_64: QEMU_GMS_SELECTIVE_SUMMARY_V1 loaded=2 matched=7 consumed=7 unsupported=7
// COUNTERS-I386: QEMU_GMS_SELECTIVE_SUMMARY_V1 loaded=2 matched=7 consumed=7 unsupported=7
