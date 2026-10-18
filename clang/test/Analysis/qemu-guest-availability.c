// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.qemu.GuestMemorySafety -analyzer-config alpha.qemu.GuestMemorySafety:ReportLevelC=true -analyzer-output=text -verify=levelc,both %s
// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.qemu.GuestMemorySafety -analyzer-output=text -verify=default,both %s

typedef __SIZE_TYPE__ size_t;
typedef __UINT64_TYPE__ uint64_t;

void *malloc(size_t);
void *g_malloc(size_t);
void *g_malloc0(size_t);
void *g_try_malloc(size_t);
void *g_realloc(void *, size_t);
void *g_malloc_n(size_t, size_t);
void *g_malloc0_n(size_t, size_t);
void *g_realloc_n(void *, size_t, size_t);
void *g_memdup2(const void *, size_t);
void *qemu_memalign(size_t, size_t);

typedef struct MemoryRegionOps {
  uint64_t (*read)(void *, uint64_t, unsigned);
  void (*write)(void *, uint64_t, uint64_t, unsigned);
} MemoryRegionOps;

static void unbounded_g_malloc(void *opaque, uint64_t addr, // levelc-note {{MMIO callback parameter 'data' is guest-controlled}}
                               uint64_t data, unsigned size) {
  g_malloc(data); // levelc-warning {{Level C: guest-controlled allocation size in g_malloc has no proven upper bound below its integer type maximum}}
                  // levelc-note@-1 {{Level C: guest-controlled allocation size in g_malloc has no proven upper bound below its integer type maximum}}
}

static const MemoryRegionOps unbounded_g_malloc_ops = {
    .write = unbounded_g_malloc,
};

static void bounded_g_malloc(void *opaque, uint64_t addr, uint64_t data,
                             unsigned size) {
  if (data > 4096)
    return;
  g_malloc(data);
}

static const MemoryRegionOps bounded_g_malloc_ops = {
    .write = bounded_g_malloc,
};

static void unbounded_g_malloc_n(void *opaque, uint64_t addr, // levelc-note {{MMIO callback parameter 'data' is guest-controlled}}
                                 uint64_t data, unsigned size) {
  g_malloc_n(data, 4); // levelc-warning {{Level C: guest-controlled allocation count in g_malloc_n has no proven upper bound below its integer type maximum}}
                       // levelc-note@-1 {{Level C: guest-controlled allocation count in g_malloc_n has no proven upper bound below its integer type maximum}}
}

static const MemoryRegionOps unbounded_g_malloc_n_ops = {
    .write = unbounded_g_malloc_n,
};

static void unbounded_g_realloc_n_element_size(
    void *opaque, uint64_t addr, // levelc-note@-1 {{MMIO callback parameter 'addr' is guest-controlled}}
    uint64_t data, unsigned size) {
  if (data > 8) // levelc-note {{Assuming 'data' is <= 8}} levelc-note {{Taking false branch}}
    return;
  g_realloc_n(opaque, data, addr); // levelc-warning {{Level C: guest-controlled allocation element size in g_realloc_n has no proven upper bound below its integer type maximum}}
                                    // levelc-note@-1 {{Level C: guest-controlled allocation element size in g_realloc_n has no proven upper bound below its integer type maximum}}
}

static const MemoryRegionOps unbounded_g_realloc_n_element_size_ops = {
    .write = unbounded_g_realloc_n_element_size,
};

static void unbounded_g_realloc(void *opaque, uint64_t addr, // levelc-note {{MMIO callback parameter 'data' is guest-controlled}}
                                uint64_t data, unsigned size) {
  g_realloc(opaque, data); // levelc-warning {{Level C: guest-controlled allocation size in g_realloc has no proven upper bound below its integer type maximum}}
                           // levelc-note@-1 {{Level C: guest-controlled allocation size in g_realloc has no proven upper bound below its integer type maximum}}
}

static const MemoryRegionOps unbounded_g_realloc_ops = {
    .write = unbounded_g_realloc,
};

static void unbounded_qemu_memalign(void *opaque, uint64_t addr, // levelc-note {{MMIO callback parameter 'data' is guest-controlled}}
                                    uint64_t data, unsigned size) {
  qemu_memalign(16, data); // levelc-warning {{Level C: guest-controlled allocation size in qemu_memalign has no proven upper bound below its integer type maximum}}
                           // levelc-note@-1 {{Level C: guest-controlled allocation size in qemu_memalign has no proven upper bound below its integer type maximum}}
}

static const MemoryRegionOps unbounded_qemu_memalign_ops = {
    .write = unbounded_qemu_memalign,
};

static void unbounded_g_memdup2(void *opaque, uint64_t addr, // levelc-note {{MMIO callback parameter 'data' is guest-controlled}}
                                uint64_t data, unsigned size) {
  g_memdup2(opaque, data); // levelc-warning {{Level C: guest-controlled allocation size in g_memdup2 has no proven upper bound below its integer type maximum}}
                           // levelc-note@-1 {{Level C: guest-controlled allocation size in g_memdup2 has no proven upper bound below its integer type maximum}}
}

static const MemoryRegionOps unbounded_g_memdup2_ops = {
    .write = unbounded_g_memdup2,
};

static void try_allocator_is_not_fatal(void *opaque, uint64_t addr,
                                       uint64_t data, unsigned size) {
  g_try_malloc(data);
}

static const MemoryRegionOps try_allocator_is_not_fatal_ops = {
    .write = try_allocator_is_not_fatal,
};

static void libc_malloc_is_not_fatal(void *opaque, uint64_t addr,
                                     uint64_t data, unsigned size) {
  malloc(data);
}

static const MemoryRegionOps libc_malloc_is_not_fatal_ops = {
    .write = libc_malloc_is_not_fatal,
};

static void arithmetic_owned_by_level_ab(void *opaque, uint64_t addr, // both-note {{MMIO callback parameter 'data' is guest-controlled}}
                                         uint64_t data, unsigned size) {
  g_malloc(data + data); // both-warning {{Level B: guest-controlled allocation-size arithmetic may overflow}}
                         // both-note@-1 {{Level B: guest-controlled allocation-size arithmetic may overflow}}
}

static const MemoryRegionOps arithmetic_owned_by_level_ab_ops = {
    .write = arithmetic_owned_by_level_ab,
};
