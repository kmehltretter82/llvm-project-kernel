// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-output=text -verify-ignore-unexpected=note -verify=default %s 2>&1 | FileCheck %s --check-prefix=DEFAULT-X86_64 --allow-empty
// RUN: %clang_analyze_cc1 -triple i386-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-output=text -verify-ignore-unexpected=note -verify=default %s 2>&1 | FileCheck %s --check-prefix=DEFAULT-I386 --allow-empty
// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -ftrivial-auto-var-init=uninitialized \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:EnableInitializedByteTracking=true \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:SelectiveSummaryManifest=%S/../../../../validation/v3-selective-ctu-summary-pci-dma-stage1/current-d7314928-stage1-v2.json \
// RUN:   -DQEMU_SELECTIVE_SUMMARY_INIT -verify=init %s
// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:SelectiveSummaryManifest=%S/../../../../validation/v3-selective-ctu-summary-pci-dma-stage1/current-d7314928-stage1-v2.json \
// RUN:   -DQEMU_SELECTIVE_SUMMARY_BOUNDS \
// RUN:   -analyzer-output=text -verify-ignore-unexpected=note -verify=bounds %s
// RUN: %clang_analyze_cc1 -triple i386-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:SelectiveSummaryManifest=%S/../../../../validation/v3-selective-ctu-summary-pci-dma-stage1/current-d7314928-stage1-v2.json \
// RUN:   -DQEMU_SELECTIVE_SUMMARY_BOUNDS \
// RUN:   -analyzer-output=text -verify-ignore-unexpected=note -verify=bounds %s
// RUN: %clang_analyze_cc1 -triple i386-unknown-linux-gnu \
// RUN:   -ftrivial-auto-var-init=uninitialized \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:EnableInitializedByteTracking=true \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:SelectiveSummaryManifest=%S/../../../../validation/v3-selective-ctu-summary-pci-dma-stage1/current-d7314928-stage1-v2.json \
// RUN:   -DQEMU_SELECTIVE_SUMMARY_INIT -verify=init %s
// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:EnableDMATransferResultDiagnostics=true \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:SelectiveSummaryManifest=%S/../../../../validation/v3-selective-ctu-summary-pci-dma-stage1/current-d7314928-stage1-v2.json \
// RUN:   -DQEMU_SELECTIVE_SUMMARY_ENABLED \
// RUN:   -analyzer-output=text -verify-ignore-unexpected=note -verify=summary %s 2>&1 | FileCheck %s --check-prefix=COUNTERS-X86_64
// RUN: %clang_analyze_cc1 -triple i386-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:EnableDMATransferResultDiagnostics=true \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:SelectiveSummaryManifest=%S/../../../../validation/v3-selective-ctu-summary-pci-dma-stage1/current-d7314928-stage1-v2.json \
// RUN:   -DQEMU_SELECTIVE_SUMMARY_ENABLED \
// RUN:   -analyzer-output=text -verify-ignore-unexpected=note -verify=summary %s 2>&1 | FileCheck %s --check-prefix=COUNTERS-I386
// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:EnableDMATransferResultDiagnostics=true \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:SelectiveSummaryManifest=%S/../../../../validation/v3-selective-ctu-summary-pci-dma-stage1/current-d7314928-stage1-v2.json \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:EmitStructuredWitness=true \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:QEMUSourceRoot=/qemu-test \
// RUN:   -DQEMU_SELECTIVE_SUMMARY_WITNESS -DQEMU_SELECTIVE_SUMMARY_ENABLED \
// RUN:   -analyzer-output=text %s 2>&1 | \
// RUN:   %python %S/Inputs/qemu-gms-selective-summary-witness-validate.py \
// RUN:   qemu-guest-memory-safety-selective-summary.c
// The i386 runs test target-independent checker matching and result behavior;
// the sealed producer manifest itself is x86_64 evidence.
// default-no-diagnostics
// DEFAULT-X86_64-NOT: QEMU_GMS_SELECTIVE_SUMMARY_V2
// DEFAULT-I386-NOT: QEMU_GMS_SELECTIVE_SUMMARY_V2

#line 1 "include/system/dma.h"
typedef unsigned long long dma_addr_t;
typedef unsigned int MemTxResult;
typedef __SIZE_TYPE__ size_t;
typedef struct AddressSpace AddressSpace;
typedef struct DeviceState DeviceState;
typedef struct PCIDevice PCIDevice;
typedef struct QEMUFile QEMUFile;
typedef struct ScatterGatherEntry ScatterGatherEntry;
typedef struct QEMUSGList QEMUSGList;
typedef struct MemTxAttrs {
  unsigned int unspecified : 1;
} MemTxAttrs;
typedef enum DMADirection {
  DMA_DIRECTION_TO_DEVICE = 0,
  DMA_DIRECTION_FROM_DEVICE = 1,
} DMADirection;
#define MEMTXATTRS_UNSPECIFIED ((MemTxAttrs){0})
struct AddressSpace {
  unsigned char opaque;
};
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
MemTxResult dma_memory_rw(AddressSpace *, dma_addr_t, void *, dma_addr_t,
                          DMADirection, MemTxAttrs);

#line 60 "include/hw/pci/pci_device.h"
struct PCIDevice {
  AddressSpace bus_master_as;
};

#line 238
static inline AddressSpace *pci_get_address_space(PCIDevice *dev) {
  return &dev->bus_master_as;
}

#line 256
static inline MemTxResult pci_dma_rw(PCIDevice *dev, dma_addr_t addr,
                                     void *buf, dma_addr_t len,
                                     DMADirection dir, MemTxAttrs attrs) {
  return dma_memory_rw(pci_get_address_space(dev), addr, buf, len, dir, attrs);
}

#line 276
static inline MemTxResult pci_dma_read(PCIDevice *dev, dma_addr_t addr,
                                       void *buf, dma_addr_t len) {
  return pci_dma_rw(dev, addr, buf, len, DMA_DIRECTION_TO_DEVICE,
                    MEMTXATTRS_UNSPECIFIED);
}
void qemu_put_buffer(QEMUFile *, const unsigned char *, size_t);
size_t qemu_get_buffer(QEMUFile *, unsigned char *, size_t);

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

void e1000e_ignores_result(PCIDevice *dev, dma_addr_t address, void *buffer,
                           dma_addr_t length) {
  pci_dma_read(dev, address, buffer, length);
  // summary-warning@-1 {{Level B: DMA transfer failure from 'pci_dma_read' is ignored}}
}

int pci_caller_checks_result(PCIDevice *dev, dma_addr_t address, void *buffer,
                             dma_addr_t length) {
  if (pci_dma_read(dev, address, buffer, length) != 0)
    return -1;
  return 0;
}

#ifdef QEMU_SELECTIVE_SUMMARY_ENABLED
unsigned pci_success_imports_host_write(PCIDevice *dev,
                                        dma_addr_t address) {
  unsigned index;
  unsigned slots[4] = {0};
  if (pci_dma_read(dev, address, &index, sizeof(index)) != 0)
    return 0;
  return slots[index];
  // summary-warning@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

unsigned pci_failure_does_not_import_host_write(PCIDevice *dev,
                                                 dma_addr_t address) {
  unsigned index = 0;
  unsigned slots[4] = {0};
  if (pci_dma_read(dev, address, &index, sizeof(index)) == 0)
    return 0;
  return slots[index];
}
#endif

#ifdef QEMU_SELECTIVE_SUMMARY_BOUNDS
void pci_read_checks_host_buffer_extent(PCIDevice *dev,
                                        dma_addr_t address,
                                        QEMUFile *input) {
  unsigned char buffer[4];
  dma_addr_t length;
  if (qemu_get_buffer(input, (unsigned char *)&length, sizeof(length)) !=
      sizeof(length))
    return;
  pci_dma_read(dev, address, buffer, length);
  // bounds-warning@-1 {{Level B: guest-controlled memory-operation length may exceed the host object extent}}
}
#endif

#ifdef QEMU_SELECTIVE_SUMMARY_INIT
void pci_failure_initializes_exact_prefix(PCIDevice *dev,
                                          dma_addr_t address,
                                          QEMUFile *output) {
  unsigned char buffer[8];
  if (pci_dma_read(dev, address, buffer, 4) == 0)
    return;
  qemu_put_buffer(output, buffer, sizeof(buffer));
  // init-warning@-1 {{Level A: host-read length exceeds the initialized byte prefix}}
}

void pci_failure_initializes_full_buffer(PCIDevice *dev,
                                         dma_addr_t address,
                                         QEMUFile *output) {
  unsigned char buffer[8];
  if (pci_dma_read(dev, address, buffer, sizeof(buffer)) == 0)
    return;
  qemu_put_buffer(output, buffer, sizeof(buffer));
}
#endif

// COUNTERS-X86_64: QEMU_GMS_SELECTIVE_SUMMARY_V2 loaded=3 matched=11 consumed=11 unsupported=7
// COUNTERS-I386: QEMU_GMS_SELECTIVE_SUMMARY_V2 loaded=3 matched=11 consumed=11 unsupported=7
