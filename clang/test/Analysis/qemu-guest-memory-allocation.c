// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.qemu.GuestMemorySafety -verify %s
// RUN: %clang_analyze_cc1 -triple arm64-apple-macosx -analyzer-checker=core,alpha.qemu.GuestMemorySafety -verify %s

typedef __SIZE_TYPE__ size_t;
typedef __UINT64_TYPE__ uint64_t;

void *malloc(size_t);
void *calloc(size_t, size_t);
void *g_malloc_n(size_t, size_t);
void *g_malloc0_n(size_t, size_t);
void *g_realloc_n(void *, size_t, size_t);
void *g_try_malloc_n(size_t, size_t);
void *g_try_malloc0_n(size_t, size_t);
void *g_try_realloc_n(void *, size_t, size_t);
void *g_memdup2(const void *, size_t);
void *qemu_try_memalign(size_t, size_t);
void *memset(void *, int, size_t);
void *memcpy(void *, const void *, size_t);

typedef struct MemoryRegionOps {
  uint64_t (*read)(void *, uint64_t, unsigned);
  void (*write)(void *, uint64_t, uint64_t, unsigned);
} MemoryRegionOps;

static void g_malloc_n_extent(void *opaque, uint64_t addr, uint64_t data,
                              unsigned size) {
  size_t count = 2;
  size_t element_size = 2;
  unsigned char *buffer = g_malloc_n(count, element_size);
  memset(buffer, 0, 5 + (data & 1)); // expected-warning {{Level A: guest-controlled memory-operation length exceeds the host object extent}}
}

static const MemoryRegionOps g_malloc_n_extent_ops = {
    .write = g_malloc_n_extent,
};

static void g_malloc0_n_extent(void *opaque, uint64_t addr, uint64_t data,
                               unsigned size) {
  unsigned char *buffer = g_malloc0_n(2, 2);
  memset(buffer, 0, 5 + (data & 1)); // expected-warning {{Level A: guest-controlled memory-operation length exceeds the host object extent}}
}

static const MemoryRegionOps g_malloc0_n_extent_ops = {
    .write = g_malloc0_n_extent,
};

static void g_realloc_n_extent(void *opaque, uint64_t addr, uint64_t data,
                               unsigned size) {
  unsigned char *buffer = g_realloc_n(opaque, 2, 2);
  memset(buffer, 0, 5 + (data & 1)); // expected-warning {{Level A: guest-controlled memory-operation length exceeds the host object extent}}
}

static const MemoryRegionOps g_realloc_n_extent_ops = {
    .write = g_realloc_n_extent,
};

static void g_try_malloc_n_extent(void *opaque, uint64_t addr, uint64_t data,
                                  unsigned size) {
  unsigned char *buffer = g_try_malloc_n(2, 2);
  if (!buffer)
    return;
  memset(buffer, 0, 5 + (data & 1)); // expected-warning {{Level A: guest-controlled memory-operation length exceeds the host object extent}}
}

static const MemoryRegionOps g_try_malloc_n_extent_ops = {
    .write = g_try_malloc_n_extent,
};

static void g_try_malloc0_n_extent(void *opaque, uint64_t addr, uint64_t data,
                                   unsigned size) {
  unsigned char *buffer = g_try_malloc0_n(2, 2);
  if (!buffer)
    return;
  memset(buffer, 0, 5 + (data & 1)); // expected-warning {{Level A: guest-controlled memory-operation length exceeds the host object extent}}
}

static const MemoryRegionOps g_try_malloc0_n_extent_ops = {
    .write = g_try_malloc0_n_extent,
};

static void g_try_realloc_n_extent(void *opaque, uint64_t addr, uint64_t data,
                                   unsigned size) {
  unsigned char *buffer = g_try_realloc_n(opaque, 2, 2);
  if (!buffer)
    return;
  memset(buffer, 0, 5 + (data & 1)); // expected-warning {{Level A: guest-controlled memory-operation length exceeds the host object extent}}
}

static const MemoryRegionOps g_try_realloc_n_extent_ops = {
    .write = g_try_realloc_n_extent,
};

static void g_memdup2_extent(void *opaque, uint64_t addr, uint64_t data,
                             unsigned size) {
  unsigned char *buffer = g_memdup2(opaque, 4);
  memset(buffer, 0, 5 + (data & 1)); // expected-warning {{Level A: guest-controlled memory-operation length exceeds the host object extent}}
}

static const MemoryRegionOps g_memdup2_extent_ops = {
    .write = g_memdup2_extent,
};

static void qemu_try_memalign_extent(void *opaque, uint64_t addr,
                                     uint64_t data, unsigned size) {
  unsigned char *buffer = qemu_try_memalign(8, 4);
  if (!buffer)
    return;
  memset(buffer, 0, 5 + (data & 1)); // expected-warning {{Level A: guest-controlled memory-operation length exceeds the host object extent}}
}

static const MemoryRegionOps qemu_try_memalign_extent_ops = {
    .write = qemu_try_memalign_extent,
};

static void calloc_extent(void *opaque, uint64_t addr, uint64_t data,
                          unsigned size) {
  unsigned char *buffer = calloc(2, 2);
  if (!buffer)
    return;
  memset(buffer, 0, 5 + (data & 1)); // expected-warning {{Level A: guest-controlled memory-operation length exceeds the host object extent}}
}

static const MemoryRegionOps calloc_extent_ops = {
    .write = calloc_extent,
};

static void checked_product_safe(void *opaque, uint64_t addr, uint64_t data,
                                 unsigned size) {
  unsigned char *buffer = g_malloc_n(data, 4);
  memset(buffer, 0, data * 4);
}

static const MemoryRegionOps checked_product_safe_ops = {
    .write = checked_product_safe,
};

static void checked_product_changed_operand(void *opaque, uint64_t addr,
                                            uint64_t data, unsigned size) {
  size_t count = data & 3;
  unsigned char *buffer = g_malloc_n(count, 4);
  count++;
  memset(buffer, 0, count * 4); // expected-warning {{guest-controlled memory-operation length}}
}

static const MemoryRegionOps checked_product_changed_operand_ops = {
    .write = checked_product_changed_operand,
};

static void checked_product_independent_same_range(
    void *opaque, uint64_t addr, uint64_t data, unsigned size) {
  size_t count = data & 3;
  size_t independent = addr & 3;
  unsigned char *buffer = g_malloc_n(count, 4);
  memset(buffer, 0, independent * 4); // expected-warning {{Level B: guest-controlled memory-operation length may exceed the host object extent}}
}

static const MemoryRegionOps checked_product_independent_same_range_ops = {
    .write = checked_product_independent_same_range,
};

static void local_wrapped_allocation(
    void *opaque, uint64_t addr, uint64_t data, unsigned size) {
  if (data <= ((uint64_t)-1) / 2)
    return;
  size_t allocation_size = data + data;
  unsigned char *buffer = malloc(allocation_size); // expected-warning {{Level B: guest-controlled allocation-size arithmetic overflows}}
  if (!buffer)
    return;
  memcpy(buffer, opaque, data); // expected-warning {{Level A: guest-controlled memory-operation length exceeds the host object extent}}
}

static const MemoryRegionOps local_wrapped_allocation_ops = {
    .write = local_wrapped_allocation,
};

static void stale_local_initializer(void *opaque, uint64_t addr,
                                    uint64_t data, unsigned size) {
  size_t allocation_size = data + data;
  allocation_size = 4;
  malloc(allocation_size);
}

static const MemoryRegionOps stale_local_initializer_ops = {
    .write = stale_local_initializer,
};
