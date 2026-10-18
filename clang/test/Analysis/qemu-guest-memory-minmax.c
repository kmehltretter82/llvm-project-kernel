// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.qemu.GuestMemorySafety -verify %s

typedef __SIZE_TYPE__ size_t;
typedef __UINT64_TYPE__ uint64_t;

void *memset(void *, int, size_t);

typedef struct MemoryRegionOps {
  uint64_t (*read)(void *, uint64_t, unsigned);
  void (*write)(void *, uint64_t, uint64_t, unsigned);
} MemoryRegionOps;

#define TEST_MIN(a, b)                                                        \
  ({                                                                          \
    typeof(1 ? (a) : (b)) test_a = (a), test_b = (b);                         \
    test_a < test_b ? test_a : test_b;                                        \
  })

#define TEST_MAX(a, b)                                                        \
  ({                                                                          \
    typeof(1 ? (a) : (b)) test_a = (a), test_b = (b);                         \
    test_a > test_b ? test_a : test_b;                                        \
  })

static void min_range_is_safe(void *opaque, uint64_t addr, uint64_t data,
                              unsigned size) {
  unsigned char buffer[4];
  memset(buffer, 0, TEST_MIN(data, sizeof(buffer)));
}

static const MemoryRegionOps min_range_is_safe_ops = {
    .write = min_range_is_safe,
};

static void max_range_is_unsafe(void *opaque, uint64_t addr, uint64_t data,
                                unsigned size) {
  unsigned char buffer[4];
  memset(buffer, 0, TEST_MAX(data, 5)); // expected-warning {{Level A: guest-controlled memory-operation length exceeds the host object extent}}
}

static const MemoryRegionOps max_range_is_unsafe_ops = {
    .write = max_range_is_unsafe,
};

static void side_effecting_min_is_unknown(void *opaque, uint64_t addr,
                                          uint64_t data, unsigned size) {
  unsigned char buffer[4];
  size_t length = data;
  memset(buffer, 0, TEST_MIN(length++, sizeof(buffer))); // expected-warning {{Level B: guest-controlled memory-operation length may exceed the host object extent}}
}

static const MemoryRegionOps side_effecting_min_is_unknown_ops = {
    .write = side_effecting_min_is_unknown,
};
