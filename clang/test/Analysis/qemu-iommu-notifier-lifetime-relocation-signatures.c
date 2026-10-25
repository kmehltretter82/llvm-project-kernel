// RUN: %clang_analyze_cc1 -DWRONG_RETURN -analyzer-checker=core,alpha.qemu.IOMMUNotifierLifetime \
// RUN:   -analyzer-config ipa=inlining -verify %s
// RUN: %clang_analyze_cc1 -DWRONG_LENGTH -analyzer-checker=core,alpha.qemu.IOMMUNotifierLifetime \
// RUN:   -analyzer-config ipa=inlining -verify %s
// expected-no-diagnostics

typedef unsigned guint;
typedef unsigned long long hwaddr;
typedef unsigned IOMMUNotifierFlag;
typedef struct Error Error;
typedef struct MemoryRegion {
  struct MemoryRegion *alias;
} MemoryRegion;
typedef struct IOMMUTLBEntry {
  int value;
} IOMMUTLBEntry;

struct IOMMUNotifier;
typedef void (*IOMMUNotify)(struct IOMMUNotifier *, IOMMUTLBEntry *);
typedef struct IOMMUNotifier {
  IOMMUNotify notify;
  IOMMUNotifierFlag notifier_flags;
  hwaddr start;
  hwaddr end;
  int iommu_idx;
  void *opaque;
} IOMMUNotifier;

typedef struct InlineNotifier {
  IOMMUNotifier notifier;
} InlineNotifier;

#line 1 "/usr/include/glib-2.0/glib/garray.h"
typedef struct _GArray {
  char *data;
  guint len;
} GArray;
#if defined(WRONG_RETURN)
void g_array_set_size(GArray *array, guint length);
#elif defined(WRONG_LENGTH)
GArray *g_array_set_size(GArray *array, int length);
#endif
#line 45 "qemu-iommu-notifier-lifetime-relocation-signatures.c"

void iommu_notifier_init(IOMMUNotifier *n, IOMMUNotify fn,
                         IOMMUNotifierFlag flags, hwaddr start, hwaddr end,
                         int iommu_idx);
int memory_region_register_iommu_notifier(MemoryRegion *mr,
                                           IOMMUNotifier *n, Error **errp);

static void notify(IOMMUNotifier *notifier, IOMMUTLBEntry *entry) {}

void wrong_garray_signature(MemoryRegion *region, GArray *array) {
  InlineNotifier *entries = (InlineNotifier *)array->data;
  iommu_notifier_init(&entries[0].notifier, notify, 1, 0, 4095, 0);
  if (memory_region_register_iommu_notifier(region, &entries[0].notifier, 0) ==
      0)
    (void)g_array_set_size(array, array->len + 1);
}
