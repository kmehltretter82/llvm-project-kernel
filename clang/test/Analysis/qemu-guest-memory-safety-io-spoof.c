// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.qemu.GuestMemorySafety -verify %s
// expected-no-diagnostics

typedef __SIZE_TYPE__ size_t;

typedef struct NetClientState NetClientState;
typedef struct BdrvChild BdrvChild;

struct iovec {
  void *iov_base;
  size_t iov_len;
};

/* Same names, but deliberately incompatible with the QEMU APIs. */
unsigned iov_to_buf_full(void *, unsigned, size_t, unsigned *, size_t);
long bdrv_co_pread(BdrvChild *, long long, long long, void *, unsigned);

typedef struct NetClientInfo {
  long (*receive_iov)(NetClientState *, const struct iovec *, int);
} NetClientInfo;

static long spoofed_iovec_helper(NetClientState *client,
                                 const struct iovec *iov, int iovcnt) {
  unsigned index;
  int slots[4] = {0};
  (void)iov_to_buf_full((void *)iov, (unsigned)iovcnt, 0, &index,
                        sizeof(index));
  return slots[index];
}

static unsigned spoofed_block_helper(BdrvChild *child) {
  unsigned index;
  int slots[4] = {0};
  (void)bdrv_co_pread(child, 0, sizeof(index), &index, 0);
  return slots[index];
}

static const NetClientInfo callback = {
    .receive_iov = spoofed_iovec_helper,
};
