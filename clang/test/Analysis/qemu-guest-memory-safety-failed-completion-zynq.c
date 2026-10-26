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
//
// disabled-no-diagnostics

typedef __UINT8_TYPE__ uint8_t;
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

typedef struct XlnxZynqDevcfg {
  AddressSpace *dma_as;
  uint8_t dma_cmd_fifo_num;
  unsigned mode;
} XlnxZynqDevcfg;

MemTxResult dma_memory_read(AddressSpace *, dma_addr_t, void *, dma_addr_t,
                            MemTxAttrs);
MemTxResult dma_memory_write(AddressSpace *, dma_addr_t, const void *,
                             dma_addr_t, MemTxAttrs);
void xlnx_zynq_devcfg_update_ixr(XlnxZynqDevcfg *);

enum {
  MODE_READ_FAILURE_COMPLETES,
  MODE_WRITE_FAILURE_COMPLETES,
  MODE_CHECKED_RESULT,
};

#line 1 "hw/dma/xlnx-zynq-devcfg.c"
static void xlnx_zynq_devcfg_dma_go(XlnxZynqDevcfg *s)
{
  uint8_t buffer[16] = {0};
  MemTxResult result;

  if (s->mode == MODE_READ_FAILURE_COMPLETES) {
    dma_memory_read(s->dma_as, 0, buffer, sizeof(buffer),
                    MEMTXATTRS_UNSPECIFIED);
    s->dma_cmd_fifo_num--;
    xlnx_zynq_devcfg_update_ixr(s); // enabled-warning {{failed DMA transfer advances device completion state and reaches transfer completion}}
    return;
  }

  if (s->mode == MODE_WRITE_FAILURE_COMPLETES) {
    dma_memory_write(s->dma_as, 0, buffer, sizeof(buffer),
                     MEMTXATTRS_UNSPECIFIED);
    s->dma_cmd_fifo_num--;
    xlnx_zynq_devcfg_update_ixr(s); // enabled-warning {{failed DMA transfer advances device completion state and reaches transfer completion}}
    return;
  }

  result = dma_memory_read(s->dma_as, 0, buffer, sizeof(buffer),
                           MEMTXATTRS_UNSPECIFIED);
  if (result != MEMTX_OK)
    return;
  s->dma_cmd_fifo_num--;
  xlnx_zynq_devcfg_update_ixr(s);
}
