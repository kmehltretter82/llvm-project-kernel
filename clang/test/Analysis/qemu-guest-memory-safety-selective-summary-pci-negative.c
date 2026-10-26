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
// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu -DWRONG_OWNER \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:EnableDMATransferResultDiagnostics=true \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:SelectiveSummaryManifest=%S/../../../../validation/v3-selective-ctu-summary-pci-dma-stage1/current-d7314928-stage1-v2.json \
// RUN:   -verify %s 2>&1 | FileCheck %s --check-prefix=COUNTERS-X86_64
// RUN: %clang_analyze_cc1 -triple i386-unknown-linux-gnu -DWRONG_OWNER \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:EnableDMATransferResultDiagnostics=true \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:SelectiveSummaryManifest=%S/../../../../validation/v3-selective-ctu-summary-pci-dma-stage1/current-d7314928-stage1-v2.json \
// RUN:   -verify %s 2>&1 | FileCheck %s --check-prefix=COUNTERS-I386
// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu -DWRONG_PROTOTYPE \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:EnableDMATransferResultDiagnostics=true \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:SelectiveSummaryManifest=%S/../../../../validation/v3-selective-ctu-summary-pci-dma-stage1/current-d7314928-stage1-v2.json \
// RUN:   -verify %s 2>&1 | FileCheck %s --check-prefix=COUNTERS-X86_64
// RUN: %clang_analyze_cc1 -triple i386-unknown-linux-gnu -DWRONG_PROTOTYPE \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:EnableDMATransferResultDiagnostics=true \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:SelectiveSummaryManifest=%S/../../../../validation/v3-selective-ctu-summary-pci-dma-stage1/current-d7314928-stage1-v2.json \
// RUN:   -verify %s 2>&1 | FileCheck %s --check-prefix=COUNTERS-I386
// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu -DWRONG_DIRECTION \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:EnableDMATransferResultDiagnostics=true \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:SelectiveSummaryManifest=%S/../../../../validation/v3-selective-ctu-summary-pci-dma-stage1/current-d7314928-stage1-v2.json \
// RUN:   -verify %s 2>&1 | FileCheck %s --check-prefix=COUNTERS-X86_64
// RUN: %clang_analyze_cc1 -triple i386-unknown-linux-gnu -DWRONG_DIRECTION \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:EnableDMATransferResultDiagnostics=true \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:SelectiveSummaryManifest=%S/../../../../validation/v3-selective-ctu-summary-pci-dma-stage1/current-d7314928-stage1-v2.json \
// RUN:   -verify %s 2>&1 | FileCheck %s --check-prefix=COUNTERS-I386
// expected-no-diagnostics

typedef unsigned long long dma_addr_t;
typedef unsigned int MemTxResult;
typedef struct AddressSpace AddressSpace;
typedef struct PCIDevice PCIDevice;

#if defined(WRONG_PROTOTYPE)

#line 276 "include/hw/pci/pci_device.h"
              MemTxResult pci_dma_read(PCIDevice *, dma_addr_t, unsigned int);

#line 1 "selective-summary-pci-wrong-prototype.c"
void exercise(PCIDevice *dev) {
  pci_dma_read(dev, 0, 4);
}

#elif defined(WRONG_DIRECTION)

#line 276 "include/hw/pci/pci_device.h"
              MemTxResult pci_dma_write(PCIDevice *, dma_addr_t, const void *,
                                        dma_addr_t);

#line 1 "selective-summary-pci-wrong-direction.c"
void exercise(PCIDevice *dev, const void *buffer, dma_addr_t length) {
  pci_dma_write(dev, 0, buffer, length);
}

#elif defined(WRONG_OWNER)

#line 60 "include/hw/pci/pci_device.h"
struct AddressSpace {
  unsigned char opaque;
};
struct PCIDevice {
  AddressSpace not_bus_master_as;
};

#line 276
              MemTxResult pci_dma_read(PCIDevice *, dma_addr_t, void *,
                                       dma_addr_t);

#line 1 "selective-summary-pci-wrong-owner.c"
void exercise(PCIDevice *dev, void *buffer, dma_addr_t length) {
  pci_dma_read(dev, 0, buffer, length);
}

#else

/* Exact name and prototype, but not the manifest-bound header declaration. */
MemTxResult pci_dma_read(PCIDevice *, dma_addr_t, void *, dma_addr_t);

void exercise(PCIDevice *dev, void *buffer, dma_addr_t length) {
  pci_dma_read(dev, 0, buffer, length);
}

#endif

// COUNTERS-X86_64: QEMU_GMS_SELECTIVE_SUMMARY_V2 loaded=3 matched=0 consumed=0 unsupported=0
// COUNTERS-I386: QEMU_GMS_SELECTIVE_SUMMARY_V2 loaded=3 matched=0 consumed=0 unsupported=0
