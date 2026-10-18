// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.qemu.GuestMemorySafety -analyzer-output=text -verify %s

typedef __SIZE_TYPE__ size_t;
typedef __UINT64_TYPE__ uint64_t;

typedef struct VirtIODevice VirtIODevice;
typedef struct NetClientState NetClientState;
typedef struct BdrvChild BdrvChild;
typedef struct BlockBackend BlockBackend;

struct iovec {
  void *iov_base;
  size_t iov_len;
};

typedef struct QEMUIOVector {
  struct iovec *iov;
  int niov;
  int nalloc;
  size_t size;
} QEMUIOVector;

size_t iov_to_buf_full(const struct iovec *, unsigned, size_t, void *, size_t);
size_t iov_from_buf_full(const struct iovec *, unsigned, size_t, const void *,
                         size_t);
unsigned iov_copy(struct iovec *, unsigned, const struct iovec *, unsigned,
                  size_t, size_t);
size_t qemu_iovec_to_buf(QEMUIOVector *, size_t, void *, size_t);
size_t qemu_iovec_from_buf(QEMUIOVector *, size_t, const void *, size_t);
void qemu_iovec_init(QEMUIOVector *, int);
void qemu_iovec_init_external(QEMUIOVector *, struct iovec *, int);
void qemu_iovec_init_slice(QEMUIOVector *, QEMUIOVector *, size_t, size_t);
void qemu_iovec_add(QEMUIOVector *, void *, size_t);
void qemu_iovec_concat(QEMUIOVector *, QEMUIOVector *, size_t, size_t);
size_t qemu_iovec_concat_iov(QEMUIOVector *, struct iovec *, unsigned, size_t,
                             size_t);
void qemu_iovec_clone(QEMUIOVector *, const QEMUIOVector *, void *);
void qemu_iovec_destroy(QEMUIOVector *);
void qemu_iovec_reset(QEMUIOVector *);
void *g_memdup2(const void *, size_t);
int bdrv_co_pread(BdrvChild *, long long, long long, void *, unsigned);
int blk_pread(BlockBackend *, long long, long long, void *, unsigned);

typedef struct NetClientInfo {
  long (*receive_iov)(NetClientState *, const struct iovec *, int);
} NetClientInfo;

typedef struct VirtioDeviceClass {
  void (*set_features)(VirtIODevice *, uint64_t);
} VirtioDeviceClass;

static long raw_iovec_full_copy(NetClientState *client, // expected-note {{network receive populated guest-controlled data here}}
                                const struct iovec *iov, int iovcnt) {
  unsigned index;
  int slots[4] = {0};
  if (iov_to_buf_full(iov, (unsigned)iovcnt, 0, &index, sizeof(index)) !=
      sizeof(index)) // expected-note {{Taking false branch}}
    return 0;
  return slots[index]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                       // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static long raw_iovec_short_copy_is_not_a_source(NetClientState *client,
                                                  const struct iovec *iov,
                                                  int iovcnt) {
  unsigned index;
  int slots[4] = {0};
  if (iov_to_buf_full(iov, (unsigned)iovcnt, 0, &index, sizeof(index)) ==
      sizeof(index))
    return 0;
  return slots[index];
}

static long copied_iovec(NetClientState *client, // expected-note {{network receive populated guest-controlled data here}}
                         const struct iovec *iov, int iovcnt) {
  struct iovec copy[4];
  unsigned index;
  int slots[4] = {0};
  (void)iov_copy(copy, 4, iov, (unsigned)iovcnt, 0, sizeof(index));
  if (iov_to_buf_full(copy, 4, 0, &index, sizeof(index)) !=
      sizeof(index)) // expected-note {{Taking false branch}}
    return 0;
  return slots[index]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                       // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static long failed_iovec_copy_is_not_a_source(NetClientState *client,
                                               const struct iovec *iov,
                                               int iovcnt) {
  struct iovec copy[4];
  unsigned index;
  int slots[4] = {0};
  if (iov_copy(copy, 4, iov, (unsigned)iovcnt, 0, sizeof(index)) != 0)
    return 0;
  if (iov_to_buf_full(copy, 4, 0, &index, sizeof(index)) != sizeof(index))
    return 0;
  return slots[index];
}

static long duplicated_iovec(NetClientState *client, // expected-note {{network receive populated guest-controlled data here}}
                             const struct iovec *iov, int iovcnt) {
  struct iovec *copy = g_memdup2(iov, (size_t)iovcnt * sizeof(*iov));
  unsigned index;
  int slots[4] = {0};
  if (iov_to_buf_full(copy, (unsigned)iovcnt, 0, &index, sizeof(index)) !=
      sizeof(index)) // expected-note {{Taking false branch}}
    return 0;
  return slots[index]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                       // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static long external_qiov(NetClientState *client, // expected-note {{network receive populated guest-controlled data here}}
                          const struct iovec *iov, int iovcnt) {
  QEMUIOVector qiov;
  unsigned index;
  int slots[4] = {0};
  qemu_iovec_init_external(&qiov, (struct iovec *)iov, iovcnt);
  if (qemu_iovec_to_buf(&qiov, 0, &index, sizeof(index)) !=
      sizeof(index)) // expected-note {{Taking false branch}}
    return 0;
  return slots[index]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                       // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static long sliced_and_cloned_qiov(NetClientState *client, // expected-note {{network receive populated guest-controlled data here}}
                                   const struct iovec *iov, int iovcnt) {
  QEMUIOVector source, slice, clone;
  unsigned index;
  int slots[4] = {0};
  qemu_iovec_init_external(&source, (struct iovec *)iov, iovcnt);
  qemu_iovec_init_slice(&slice, &source, 0, sizeof(index));
  qemu_iovec_clone(&clone, &slice, 0);
  if (qemu_iovec_to_buf(&clone, 0, &index, sizeof(index)) !=
      sizeof(index)) // expected-note {{Taking false branch}}
    return 0;
  return slots[index]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                       // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static long concatenated_qiov(NetClientState *client, // expected-note {{network receive populated guest-controlled data here}}
                              const struct iovec *iov, int iovcnt) {
  struct iovec trusted = {0};
  QEMUIOVector source, destination;
  unsigned index;
  int slots[4] = {0};
  qemu_iovec_init_external(&source, (struct iovec *)iov, iovcnt);
  qemu_iovec_init_external(&destination, &trusted, 1);
  qemu_iovec_concat(&destination, &source, 0, sizeof(index));
  if (qemu_iovec_to_buf(&destination, 0, &index, sizeof(index)) !=
      sizeof(index)) // expected-note {{Taking false branch}}
    return 0;
  return slots[index]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                       // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static long concatenated_raw_iov(NetClientState *client, // expected-note {{network receive populated guest-controlled data here}}
                                 const struct iovec *iov, int iovcnt) {
  QEMUIOVector destination;
  unsigned index;
  int slots[4] = {0};
  qemu_iovec_init(&destination, 1);
  (void)qemu_iovec_concat_iov(&destination, (struct iovec *)iov,
                              (unsigned)iovcnt, 0, sizeof(index));
  if (qemu_iovec_to_buf(&destination, 0, &index, sizeof(index)) !=
      sizeof(index)) // expected-note {{Taking false branch}}
    return 0;
  return slots[index]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                       // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static long destroyed_qiov_is_not_a_source(NetClientState *client,
                                            const struct iovec *iov,
                                            int iovcnt) {
  QEMUIOVector qiov;
  unsigned index;
  int slots[4] = {0};
  qemu_iovec_init_external(&qiov, (struct iovec *)iov, iovcnt);
  qemu_iovec_destroy(&qiov);
  qemu_iovec_init(&qiov, 1);
  qemu_iovec_add(&qiov, &index, sizeof(index));
  if (qemu_iovec_to_buf(&qiov, 0, &index, sizeof(index)) != sizeof(index))
    return 0;
  return slots[index];
}

static long reset_qiov_is_not_a_source(NetClientState *client,
                                        const struct iovec *iov, int iovcnt) {
  QEMUIOVector qiov;
  unsigned index;
  int slots[4] = {0};
  qemu_iovec_init_external(&qiov, (struct iovec *)iov, iovcnt);
  qemu_iovec_reset(&qiov);
  qemu_iovec_add(&qiov, &index, sizeof(index));
  if (qemu_iovec_to_buf(&qiov, 0, &index, sizeof(index)) != sizeof(index))
    return 0;
  return slots[index];
}

static const NetClientInfo iovec_callbacks[] = {
    {.receive_iov = raw_iovec_full_copy},
    {.receive_iov = raw_iovec_short_copy_is_not_a_source},
    {.receive_iov = copied_iovec},
    {.receive_iov = failed_iovec_copy_is_not_a_source},
    {.receive_iov = duplicated_iovec},
    {.receive_iov = external_qiov},
    {.receive_iov = sliced_and_cloned_qiov},
    {.receive_iov = concatenated_qiov},
    {.receive_iov = concatenated_raw_iov},
    {.receive_iov = destroyed_qiov_is_not_a_source},
    {.receive_iov = reset_qiov_is_not_a_source},
};

static unsigned bdrv_co_index(BdrvChild *child) {
  unsigned index;
  int slots[4] = {0};
  if (bdrv_co_pread(child, 0, sizeof(index), &index, 0) != 0) // expected-note {{disk-image read populated guest-controlled data here}}
                                                               // expected-note@-1 {{Taking false branch}}
    return 0;
  return slots[index]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                       // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static unsigned blk_index(BlockBackend *backend) {
  unsigned index;
  int slots[4] = {0};
  if (blk_pread(backend, 0, sizeof(index), &index, 0) != 0) // expected-note {{disk-image read populated guest-controlled data here}}
                                                             // expected-note@-1 {{Taking false branch}}
    return 0;
  return slots[index]; // expected-warning {{Level B: guest-controlled array index may exceed the host object element count}}
                       // expected-note@-1 {{Level B: guest-controlled array index may exceed the host object element count}}
}

static unsigned failed_blk_read_is_not_a_source(BlockBackend *backend) {
  unsigned index;
  int slots[4] = {0};
  if (blk_pread(backend, 0, sizeof(index), &index, 0) == 0)
    return 0;
  return slots[index];
}

static void raw_iovec_from_buf_overread(VirtIODevice *vdev, // expected-note {{virtio configuration callback parameter 'bytes' is guest-controlled}}
                                        uint64_t bytes) {
  struct iovec iov = {0};
  unsigned char source[4] = {0};
  (void)iov_from_buf_full(&iov, 1, 0, source, bytes); // expected-warning {{Level B: guest-controlled memory-operation source length may exceed the host object extent}}
                                                      // expected-note@-1 {{Level B: guest-controlled memory-operation source length may exceed the host object extent}}
}

static void qiov_from_buf_guarded(VirtIODevice *vdev, uint64_t bytes) {
  QEMUIOVector qiov = {0};
  unsigned char source[4] = {0};
  if (bytes > sizeof(source))
    return;
  (void)qemu_iovec_from_buf(&qiov, 0, source, bytes);
}

static void register_iovec_sink_callbacks(VirtioDeviceClass *vdc) {
  vdc->set_features = raw_iovec_from_buf_overread;
}

static void register_guarded_iovec_sink_callbacks(VirtioDeviceClass *vdc) {
  vdc->set_features = qiov_from_buf_guarded;
}
