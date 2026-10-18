// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.qemu.GuestMemorySafety -verify %s

typedef __SIZE_TYPE__ size_t;
typedef __UINT64_TYPE__ uint64_t;

void *malloc(size_t);
void *memcpy(void *, const void *, size_t);

typedef struct MemoryRegionOps {
  uint64_t (*read)(void *, uint64_t, unsigned);
  void (*write)(void *, uint64_t, uint64_t, unsigned);
} MemoryRegionOps;

static void allocation_overflow_alone(void *opaque, uint64_t addr,
                                      uint64_t data, unsigned size) {
  if (data <= ((uint64_t)-1) / 2)
    return;
  malloc(data + data); // expected-warning {{Level B: guest-controlled allocation-size arithmetic overflows}}
}

static const MemoryRegionOps allocation_overflow_alone_ops = {
    .write = allocation_overflow_alone,
};

static void wrapped_allocation_access(void *opaque, uint64_t addr,
                                      uint64_t data, unsigned size) {
  if (data <= ((uint64_t)-1) / 2)
    return;
  char *destination = malloc(data + data); // expected-warning {{Level B: guest-controlled allocation-size arithmetic overflows}}
  if (!destination)
    return;
  memcpy(destination, opaque, data); // expected-warning {{Level A: guest-controlled memory-operation length exceeds the host object extent}}
}

static const MemoryRegionOps wrapped_allocation_access_ops = {
    .write = wrapped_allocation_access,
};

static void unwrapped_allocation_access(void *opaque, uint64_t addr,
                                        uint64_t data, unsigned size) {
  if (data > ((uint64_t)-1) / 2)
    return;
  char *destination = malloc(data + data);
  if (!destination)
    return;
  memcpy(destination, opaque, data);
}

static const MemoryRegionOps unwrapped_allocation_access_ops = {
    .write = unwrapped_allocation_access,
};
