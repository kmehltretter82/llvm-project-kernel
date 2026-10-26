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

typedef struct RTL8139State {
  PCIDevice parent_obj;
  PCIDevice other_dev;
  struct RTL8139State *peer;
  uint32_t TxStatus[4];
  uint32_t OtherStatus[4];
  uint32_t TxAddr[4];
  uint32_t IntrStatus;
  unsigned mode;
} RTL8139State;

#define PCI_DEVICE(s) (&(s)->parent_obj)
#define TxHostOwns 0x2000
#define TxStatOK 0x8000
#define TxOK 0x0004

static void rtl8139_update_irq(RTL8139State *s) { (void)s; }

enum {
  MODE_FAILURE_COMPLETES,
  MODE_CHECKED_RESULT,
  MODE_NO_RING_ADVANCE,
  MODE_REVERSED_EVENTS,
  MODE_WRONG_RHS,
  MODE_WRONG_INDEX,
  MODE_WRONG_FIELD,
  MODE_WRONG_RING_OWNER,
  MODE_WRONG_COMPLETION_OWNER,
  MODE_WRONG_COMPLETION_CAUSE,
  MODE_NO_COMPLETION_STATUS,
  MODE_WRONG_DMA_OWNER,
  MODE_WRONG_DMA_MEMBER,
  MODE_DUPLICATE_FAILURE,
};

#if defined(WRONG_SCOPE)
#line 1 "hw/net/not-rtl8139.c"
#else
#line 1 "hw/net/rtl8139.c"
#endif
static int rtl8139_transmit_one(RTL8139State *s, int descriptor) {
  unsigned char txbuffer[0x2000];
  PCIDevice *d;
  MemTxResult result;

  if (!s || descriptor < 0 || descriptor >= 4)
    return 0;
  d = PCI_DEVICE(s);

  if (s->mode == MODE_FAILURE_COMPLETES) {
    pci_dma_read(d, s->TxAddr[descriptor], txbuffer, 60);
    s->TxStatus[descriptor] |= TxHostOwns;
    s->TxStatus[descriptor] |= TxStatOK;
    // enabled-warning@+1 {{failed DMA transfer advances device completion state}}
    s->IntrStatus |= TxOK;
    rtl8139_update_irq(s);
    return 1;
  }

  if (s->mode == MODE_CHECKED_RESULT) {
    result = pci_dma_read(d, s->TxAddr[descriptor], txbuffer, 60);
    if (result != 0)
      return 0;
    s->TxStatus[descriptor] |= TxHostOwns;
    s->IntrStatus |= TxOK;
    rtl8139_update_irq(s);
    return 1;
  }

  if (s->mode == MODE_NO_RING_ADVANCE) {
    pci_dma_read(d, s->TxAddr[descriptor], txbuffer, 60);
    s->IntrStatus |= TxOK;
    rtl8139_update_irq(s);
    return 1;
  }

  if (s->mode == MODE_REVERSED_EVENTS) {
    pci_dma_read(d, s->TxAddr[descriptor], txbuffer, 60);
    s->IntrStatus |= TxOK;
    rtl8139_update_irq(s);
    s->TxStatus[descriptor] |= TxHostOwns;
    return 1;
  }

  if (s->mode == MODE_WRONG_RHS) {
    pci_dma_read(d, s->TxAddr[descriptor], txbuffer, 60);
    s->TxStatus[descriptor] |= TxStatOK;
    s->IntrStatus |= TxOK;
    rtl8139_update_irq(s);
    return 1;
  }

  if (s->mode == MODE_WRONG_INDEX) {
    pci_dma_read(d, s->TxAddr[descriptor], txbuffer, 60);
    s->TxStatus[(descriptor + 1) & 3] |= TxHostOwns;
    s->IntrStatus |= TxOK;
    rtl8139_update_irq(s);
    return 1;
  }

  if (s->mode == MODE_WRONG_FIELD) {
    pci_dma_read(d, s->TxAddr[descriptor], txbuffer, 60);
    s->OtherStatus[descriptor] |= TxHostOwns;
    s->IntrStatus |= TxOK;
    rtl8139_update_irq(s);
    return 1;
  }

  if (s->mode == MODE_WRONG_RING_OWNER) {
    if (!s->peer)
      return 0;
    pci_dma_read(d, s->TxAddr[descriptor], txbuffer, 60);
    s->peer->TxStatus[descriptor] |= TxHostOwns;
    s->IntrStatus |= TxOK;
    rtl8139_update_irq(s);
    return 1;
  }

  if (s->mode == MODE_WRONG_COMPLETION_OWNER) {
    if (!s->peer)
      return 0;
    pci_dma_read(d, s->TxAddr[descriptor], txbuffer, 60);
    s->TxStatus[descriptor] |= TxHostOwns;
    s->peer->IntrStatus |= TxOK;
    rtl8139_update_irq(s->peer);
    return 1;
  }

  if (s->mode == MODE_WRONG_COMPLETION_CAUSE) {
    pci_dma_read(d, s->TxAddr[descriptor], txbuffer, 60);
    s->TxStatus[descriptor] |= TxHostOwns;
    s->IntrStatus |= 8;
    rtl8139_update_irq(s);
    return 1;
  }

  if (s->mode == MODE_NO_COMPLETION_STATUS) {
    pci_dma_read(d, s->TxAddr[descriptor], txbuffer, 60);
    s->TxStatus[descriptor] |= TxHostOwns;
    rtl8139_update_irq(s);
    return 1;
  }

  if (s->mode == MODE_WRONG_DMA_OWNER) {
    if (!s->peer)
      return 0;
    pci_dma_read(PCI_DEVICE(s->peer), s->TxAddr[descriptor], txbuffer, 60);
    s->TxStatus[descriptor] |= TxHostOwns;
    s->IntrStatus |= TxOK;
    rtl8139_update_irq(s);
    return 1;
  }

  if (s->mode == MODE_WRONG_DMA_MEMBER) {
    pci_dma_read(&s->other_dev, s->TxAddr[descriptor], txbuffer, 60);
    s->TxStatus[descriptor] |= TxHostOwns;
    s->IntrStatus |= TxOK;
    rtl8139_update_irq(s);
    return 1;
  }

  if (s->mode == MODE_DUPLICATE_FAILURE) {
    MemTxResult first = pci_dma_read(d, s->TxAddr[descriptor], txbuffer, 60);
    MemTxResult second = pci_dma_read(d, s->TxAddr[descriptor], txbuffer, 60);
    if (first == 0 || second == 0)
      return 0;
    s->TxStatus[descriptor] |= TxHostOwns;
    s->IntrStatus |= TxOK;
    rtl8139_update_irq(s);
    return 1;
  }

  return 0;
}

int exercise_rtl8139(RTL8139State *s, int descriptor, unsigned mode) {
  if (!s)
    return 0;
  s->mode = mode;
  return rtl8139_transmit_one(s, descriptor);
}
