// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:EnableFailedCompletionPublicationDiagnostics=true \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:SelectiveSummaryManifest=%S/../../../../validation/v3-selective-ctu-summary-pci-dma-stage1/current-d7314928-stage1-v2.json \
// RUN:   -analyzer-output=text -verify-ignore-unexpected=note -verify=enabled %s
// RUN: %clang_analyze_cc1 -triple i386-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:EnableFailedCompletionPublicationDiagnostics=true \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:SelectiveSummaryManifest=%S/../../../../validation/v3-selective-ctu-summary-pci-dma-stage1/current-d7314928-stage1-v2.json \
// RUN:   -analyzer-output=text -verify-ignore-unexpected=note -verify=enabled %s
// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:SelectiveSummaryManifest=%S/../../../../validation/v3-selective-ctu-summary-pci-dma-stage1/current-d7314928-stage1-v2.json \
// RUN:   -analyzer-output=text -verify=disabled %s
// RUN: %clang_analyze_cc1 -triple i386-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:SelectiveSummaryManifest=%S/../../../../validation/v3-selective-ctu-summary-pci-dma-stage1/current-d7314928-stage1-v2.json \
// RUN:   -analyzer-output=text -verify=disabled %s
// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu -DWRONG_SCOPE \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:EnableFailedCompletionPublicationDiagnostics=true \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:SelectiveSummaryManifest=%S/../../../../validation/v3-selective-ctu-summary-pci-dma-stage1/current-d7314928-stage1-v2.json \
// RUN:   -analyzer-output=text -verify=wrong-scope %s
// disabled-no-diagnostics
// wrong-scope-no-diagnostics

typedef __UINT32_TYPE__ uint32_t;
typedef __UINT64_TYPE__ uint64_t;
typedef uint64_t dma_addr_t;
typedef uint32_t MemTxResult;

typedef struct AddressSpace {
  unsigned char opaque;
} AddressSpace;
typedef enum DMADirection {
  DMA_DIRECTION_TO_DEVICE = 0,
  DMA_DIRECTION_FROM_DEVICE = 1,
} DMADirection;
typedef struct MemTxAttrs {
  unsigned int unspecified : 1;
} MemTxAttrs;
#define MEMTXATTRS_UNSPECIFIED ((MemTxAttrs){0})

MemTxResult dma_memory_rw(AddressSpace *, dma_addr_t, void *, dma_addr_t,
                          DMADirection, MemTxAttrs);

#line 60 "include/hw/pci/pci_device.h"
typedef struct PCIDevice {
  AddressSpace bus_master_as;
} PCIDevice;

#line 238
static inline AddressSpace *pci_get_address_space(PCIDevice *dev) {
  return &dev->bus_master_as;
}

#line 256
static inline MemTxResult pci_dma_rw(PCIDevice *dev, dma_addr_t addr, void *buf,
                                     dma_addr_t len, DMADirection dir,
                                     MemTxAttrs attrs) {
  return dma_memory_rw(pci_get_address_space(dev), addr, buf, len, dir, attrs);
}

#line 276
static inline MemTxResult pci_dma_read(PCIDevice *dev, dma_addr_t addr,
                                       void *buf, dma_addr_t len) {
  return pci_dma_rw(dev, addr, buf, len, DMA_DIRECTION_TO_DEVICE,
                    MEMTXATTRS_UNSPECIFIED);
}

typedef struct E1000Core E1000ECore;
struct E1000Core {
  PCIDevice *owner;
  PCIDevice *peer_owner;
  E1000ECore *peer;
  unsigned mode;
};

typedef struct E1000ERingInfo {
  int idx;
} E1000ERingInfo;

typedef struct E1000E_TxRing {
  const E1000ERingInfo *i;
} E1000E_TxRing;

static inline void
e1000e_ring_advance(E1000ECore *core, const E1000ERingInfo *r, uint32_t count) {
  (void)core;
  (void)r;
  (void)count;
}

void e1000e_set_interrupt_cause(E1000ECore *, uint32_t);
uint32_t e1000e_symbolic_tx_cause(void);

enum {
  MODE_FAILURE_COMPLETES,
  MODE_CHECKED_RESULT,
  MODE_NO_RING_ADVANCE,
  MODE_REVERSED_EVENTS,
  MODE_WRONG_RING_COUNT,
  MODE_WRONG_RING_OWNER,
  MODE_WRONG_RING_QUEUE,
  MODE_WRONG_COMPLETION_OWNER,
  MODE_WRONG_COMPLETION_CAUSE,
  MODE_NO_COMPLETION,
  MODE_WRONG_DMA_OWNER,
  MODE_DUPLICATE_FAILURE,
  MODE_MULTIPLE_FAILURES_COMPLETE,
  MODE_SYMBOLIC_CAUSE,
};

#if defined(WRONG_SCOPE)
#line 1 "hw/net/not-e1000e_core.c"
#else
#line 1 "hw/net/e1000e_core.c"
#endif
static void e1000e_start_xmit(E1000ECore *core, const E1000E_TxRing *txr) {
  unsigned char desc[16];
  const E1000ERingInfo *txi;
  dma_addr_t base = 0x1000;
  MemTxResult result;

  if (!core || !core->owner || !txr || !txr->i)
    return;
  txi = txr->i;

  if (core->mode == MODE_FAILURE_COMPLETES) {
    pci_dma_read(core->owner, base, desc, sizeof(desc));
    e1000e_ring_advance(core, txi, 1);
    // enabled-warning@+1 {{failed DMA transfer advances device completion state}}
    e1000e_set_interrupt_cause(core, 2);
    return;
  }

  if (core->mode == MODE_CHECKED_RESULT) {
    result = pci_dma_read(core->owner, base, desc, sizeof(desc));
    if (result != 0)
      return;
    e1000e_ring_advance(core, txi, 1);
    e1000e_set_interrupt_cause(core, 2);
    return;
  }

  if (core->mode == MODE_NO_RING_ADVANCE) {
    pci_dma_read(core->owner, base, desc, sizeof(desc));
    e1000e_set_interrupt_cause(core, 2);
    return;
  }

  if (core->mode == MODE_REVERSED_EVENTS) {
    pci_dma_read(core->owner, base, desc, sizeof(desc));
    e1000e_set_interrupt_cause(core, 2);
    e1000e_ring_advance(core, txi, 1);
    return;
  }

  if (core->mode == MODE_WRONG_RING_COUNT) {
    pci_dma_read(core->owner, base, desc, sizeof(desc));
    e1000e_ring_advance(core, txi, 2);
    e1000e_set_interrupt_cause(core, 2);
    return;
  }

  if (core->mode == MODE_WRONG_RING_OWNER) {
    pci_dma_read(core->owner, base, desc, sizeof(desc));
    e1000e_ring_advance(core->peer, txi, 1);
    e1000e_set_interrupt_cause(core, 2);
    return;
  }

  if (core->mode == MODE_WRONG_RING_QUEUE) {
    E1000ERingInfo other_ring;
    pci_dma_read(core->owner, base, desc, sizeof(desc));
    e1000e_ring_advance(core, &other_ring, 1);
    e1000e_set_interrupt_cause(core, 2);
    return;
  }

  if (core->mode == MODE_WRONG_COMPLETION_OWNER) {
    pci_dma_read(core->owner, base, desc, sizeof(desc));
    e1000e_ring_advance(core, txi, 1);
    e1000e_set_interrupt_cause(core->peer, 2);
    return;
  }

  if (core->mode == MODE_WRONG_COMPLETION_CAUSE) {
    pci_dma_read(core->owner, base, desc, sizeof(desc));
    e1000e_ring_advance(core, txi, 1);
    e1000e_set_interrupt_cause(core, 4);
    return;
  }

  if (core->mode == MODE_NO_COMPLETION) {
    pci_dma_read(core->owner, base, desc, sizeof(desc));
    e1000e_ring_advance(core, txi, 1);
    return;
  }

  if (core->mode == MODE_WRONG_DMA_OWNER) {
    if (!core->peer_owner)
      return;
    pci_dma_read(core->peer_owner, base, desc, sizeof(desc));
    e1000e_ring_advance(core, txi, 1);
    e1000e_set_interrupt_cause(core, 2);
    return;
  }

  if (core->mode == MODE_DUPLICATE_FAILURE) {
    MemTxResult first = pci_dma_read(core->owner, base, desc, sizeof(desc));
    MemTxResult second =
        pci_dma_read(core->owner, base + sizeof(desc), desc, sizeof(desc));
    if (first == 0 || second == 0)
      return;
    e1000e_ring_advance(core, txi, 1);
    e1000e_set_interrupt_cause(core, 2);
    return;
  }

  if (core->mode == MODE_MULTIPLE_FAILURES_COMPLETE) {
    pci_dma_read(core->owner, base, desc, sizeof(desc));
    e1000e_ring_advance(core, txi, 1);
    pci_dma_read(core->owner, base + sizeof(desc), desc, sizeof(desc));
    e1000e_ring_advance(core, txi, 1);
    // enabled-warning@+1 {{failed DMA transfer advances device completion state}}
    e1000e_set_interrupt_cause(core, 2);
    return;
  }

  if (core->mode == MODE_SYMBOLIC_CAUSE) {
    uint32_t cause = 2;
    pci_dma_read(core->owner, base, desc, sizeof(desc));
    cause |= e1000e_symbolic_tx_cause();
    e1000e_ring_advance(core, txi, 1);
    // enabled-warning@+1 {{failed DMA transfer advances device completion state}}
    e1000e_set_interrupt_cause(core, cause);
  }
}

void exercise_e1000e(E1000ECore *core, const E1000E_TxRing *txr,
                     unsigned mode) {
  if (!core)
    return;
  core->mode = mode;
  e1000e_start_xmit(core, txr);
}
