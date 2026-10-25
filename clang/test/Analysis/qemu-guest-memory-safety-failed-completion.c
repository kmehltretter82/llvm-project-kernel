// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:EnableFailedCompletionPublicationDiagnostics=true \
// RUN:   -analyzer-output=text -verify-ignore-unexpected=note -verify=enabled %s
// RUN: %clang_analyze_cc1 -triple i386-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:EnableFailedCompletionPublicationDiagnostics=true \
// RUN:   -analyzer-output=text -verify-ignore-unexpected=note -verify=enabled %s
// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-output=text -verify=disabled %s
// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu -DWRONG_SCOPE \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:EnableFailedCompletionPublicationDiagnostics=true \
// RUN:   -analyzer-output=text -verify=wrong-scope %s
// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu -DWRONG_SOURCE \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:EnableFailedCompletionPublicationDiagnostics=true \
// RUN:   -analyzer-output=text -verify=wrong-source %s
// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu -DWRONG_COMPLETION \
// RUN:   -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:EnableFailedCompletionPublicationDiagnostics=true \
// RUN:   -analyzer-output=text -verify=wrong-completion %s
//
// disabled-no-diagnostics
// wrong-scope-no-diagnostics
// wrong-source-no-diagnostics
// wrong-completion-no-diagnostics

typedef __UINT32_TYPE__ uint32_t;
typedef __UINT64_TYPE__ uint64_t;
typedef uint64_t dma_addr_t;

typedef struct AddressSpace AddressSpace;
typedef struct MemTxAttrs {
  unsigned int unspecified : 1;
} MemTxAttrs;
typedef uint32_t MemTxResult;

#define MEMTX_OK ((MemTxResult)0)
#define MEMTXATTRS_UNSPECIFIED ((MemTxAttrs){0})

typedef struct SDHCIState {
  AddressSpace *dma_as;
  struct SDHCIState *peer;
  unsigned mode;
  unsigned blkcnt;
  unsigned other_count;
} SDHCIState;

MemTxResult dma_memory_read(AddressSpace *, dma_addr_t, void *, dma_addr_t,
                            MemTxAttrs);
MemTxResult dma_memory_write(AddressSpace *, dma_addr_t, const void *,
                             dma_addr_t, MemTxAttrs);

#if defined(WRONG_SOURCE)

void sdhci_end_transfer(SDHCIState *);

void sdhci_do_adma(SDHCIState *s)
{
  unsigned char buffer[8] = {0};
  if (!s)
    return;
  dma_memory_write(s->dma_as, 0, buffer, sizeof(buffer),
                   MEMTXATTRS_UNSPECIFIED);
  s->blkcnt--;
  sdhci_end_transfer(s);
}

#elif defined(WRONG_SCOPE)

void sdhci_end_transfer(SDHCIState *);

#line 1 "hw/sd/sdhci.c"
void sdhci_do_adma(SDHCIState *s, unsigned unused)
{
  unsigned char buffer[8] = {0};
  if (!s)
    return;
  (void)unused;
  dma_memory_write(s->dma_as, 0, buffer, sizeof(buffer),
                   MEMTXATTRS_UNSPECIFIED);
  s->blkcnt--;
  sdhci_end_transfer(s);
}

#elif defined(WRONG_COMPLETION)

void sdhci_end_transfer(SDHCIState *, unsigned);

#line 1 "hw/sd/sdhci.c"
void sdhci_do_adma(SDHCIState *s)
{
  unsigned char buffer[8] = {0};
  if (!s)
    return;
  dma_memory_write(s->dma_as, 0, buffer, sizeof(buffer),
                   MEMTXATTRS_UNSPECIFIED);
  s->blkcnt--;
  sdhci_end_transfer(s, 0);
}

#else

void sdhci_end_transfer(SDHCIState *);

enum {
  MODE_WRITE_FAILURE_COMPLETES,
  MODE_READ_FAILURE_COMPLETES,
  MODE_CHECKED_RESULT,
  MODE_NO_RING_ADVANCE,
  MODE_REVERSED_EVENTS,
  MODE_PRE_DECREMENT,
  MODE_OTHER_FIELD,
  MODE_MISMATCHED_RING_OWNER,
  MODE_MISMATCHED_COMPLETION_OWNER,
  MODE_EXIT_WITH_PENDING_FAILURE,
  MODE_RING_ONLY,
};

#line 1 "hw/sd/sdhci.c"
void sdhci_do_adma(SDHCIState *s)
{
  unsigned char buffer[8] = {0};
  MemTxResult result;
  SDHCIState *peer;

  if (!s)
    return;

  if (s->mode == MODE_WRITE_FAILURE_COMPLETES) {
    dma_memory_write(s->dma_as, 0, buffer, sizeof(buffer),
                     MEMTXATTRS_UNSPECIFIED);
    s->blkcnt--;
    sdhci_end_transfer(s); // enabled-warning {{failed DMA transfer advances device completion state and reaches transfer completion}}
    return;
  }

  if (s->mode == MODE_READ_FAILURE_COMPLETES) {
    dma_memory_read(s->dma_as, 0, buffer, sizeof(buffer),
                    MEMTXATTRS_UNSPECIFIED);
    s->blkcnt--;
    sdhci_end_transfer(s); // enabled-warning {{failed DMA transfer advances device completion state and reaches transfer completion}}
    return;
  }

  if (s->mode == MODE_CHECKED_RESULT) {
    result = dma_memory_write(s->dma_as, 0, buffer, sizeof(buffer),
                              MEMTXATTRS_UNSPECIFIED);
    if (result != MEMTX_OK)
      return;
    s->blkcnt--;
    sdhci_end_transfer(s);
    return;
  }

  if (s->mode == MODE_NO_RING_ADVANCE) {
    dma_memory_write(s->dma_as, 0, buffer, sizeof(buffer),
                     MEMTXATTRS_UNSPECIFIED);
    sdhci_end_transfer(s);
    return;
  }

  if (s->mode == MODE_REVERSED_EVENTS) {
    dma_memory_write(s->dma_as, 0, buffer, sizeof(buffer),
                     MEMTXATTRS_UNSPECIFIED);
    sdhci_end_transfer(s);
    s->blkcnt--;
    return;
  }

  if (s->mode == MODE_PRE_DECREMENT) {
    dma_memory_write(s->dma_as, 0, buffer, sizeof(buffer),
                     MEMTXATTRS_UNSPECIFIED);
    --s->blkcnt;
    sdhci_end_transfer(s);
    return;
  }

  if (s->mode == MODE_OTHER_FIELD) {
    dma_memory_write(s->dma_as, 0, buffer, sizeof(buffer),
                     MEMTXATTRS_UNSPECIFIED);
    s->other_count--;
    sdhci_end_transfer(s);
    return;
  }

  if (s->mode == MODE_MISMATCHED_RING_OWNER) {
    peer = s->peer;
    if (!peer)
      return;
    dma_memory_write(s->dma_as, 0, buffer, sizeof(buffer),
                     MEMTXATTRS_UNSPECIFIED);
    peer->blkcnt--;
    sdhci_end_transfer(s);
    return;
  }

  if (s->mode == MODE_MISMATCHED_COMPLETION_OWNER) {
    peer = s->peer;
    if (!peer)
      return;
    dma_memory_write(s->dma_as, 0, buffer, sizeof(buffer),
                     MEMTXATTRS_UNSPECIFIED);
    s->blkcnt--;
    sdhci_end_transfer(peer);
    return;
  }

  if (s->mode == MODE_EXIT_WITH_PENDING_FAILURE) {
    dma_memory_write(s->dma_as, 0, buffer, sizeof(buffer),
                     MEMTXATTRS_UNSPECIFIED);
    return;
  }

  if (s->mode == MODE_RING_ONLY) {
    s->blkcnt--;
    sdhci_end_transfer(s);
  }
}

void exercise_failed_completion_modes(SDHCIState *s, unsigned mode)
{
  if (!s)
    return;
  s->mode = mode;
  sdhci_do_adma(s);
}

void failed_publication_does_not_escape_function(SDHCIState *s)
{
  if (!s)
    return;
  s->mode = MODE_EXIT_WITH_PENDING_FAILURE;
  sdhci_do_adma(s);
  s->mode = MODE_RING_ONLY;
  sdhci_do_adma(s);
}

#endif
