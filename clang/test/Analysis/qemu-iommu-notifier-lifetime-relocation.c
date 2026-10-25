// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.qemu.IOMMUNotifierLifetime \
// RUN:   -triple x86_64-unknown-linux-gnu -analyzer-config ipa=inlining -verify %s
// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.qemu.IOMMUNotifierLifetime \
// RUN:   -triple i386-unknown-linux-gnu -analyzer-config ipa=inlining -verify %s

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

typedef struct TCGIOMMUNotifier {
  IOMMUNotifier notifier;
  MemoryRegion *region;
  int index;
} TCGIOMMUNotifier;

#line 1 "/usr/include/glib-2.0/glib/garray.h"
typedef struct _GArray {
  char *data;
  guint len;
} GArray;
GArray *g_array_set_size(GArray *array, guint length);
#line 40 "qemu-iommu-notifier-lifetime-relocation.c"

void iommu_notifier_init(IOMMUNotifier *n, IOMMUNotify fn,
                         IOMMUNotifierFlag flags, hwaddr start, hwaddr end,
                         int iommu_idx);
int memory_region_register_iommu_notifier(MemoryRegion *mr,
                                           IOMMUNotifier *n, Error **errp);
void memory_region_unregister_iommu_notifier(MemoryRegion *mr,
                                              IOMMUNotifier *n);

static void notify(IOMMUNotifier *notifier, IOMMUTLBEntry *entry) {}

void inline_notifier_storage(MemoryRegion *region, GArray *array) {
  TCGIOMMUNotifier *entries = (TCGIOMMUNotifier *)array->data;
  IOMMUNotifier *notifier = &entries[0].notifier;
  iommu_notifier_init(notifier, notify, 1, 0, 4095, 0);
  // expected-note@+1 {{Inline IOMMU notifier registered here}}
  if (memory_region_register_iommu_notifier(region, notifier, 0) == 0)
    array = g_array_set_size(array, array->len + 1); // expected-warning {{Resizing a GArray may relocate storage containing an active IOMMU notifier}}
}

void separately_allocated_notifier(MemoryRegion *region, GArray *array,
                                   TCGIOMMUNotifier *entry) {
  TCGIOMMUNotifier **entries = (TCGIOMMUNotifier **)array->data;
  entries[0] = entry;
  iommu_notifier_init(&entry->notifier, notify, 1, 0, 4095, 0);
  if (memory_region_register_iommu_notifier(region, &entry->notifier, 0) == 0)
    array = g_array_set_size(array, array->len + 1);
}

void unchanged_inline_array_size(MemoryRegion *region, GArray *array) {
  TCGIOMMUNotifier *entries = (TCGIOMMUNotifier *)array->data;
  IOMMUNotifier *notifier = &entries[0].notifier;
  iommu_notifier_init(notifier, notify, 1, 0, 4095, 0);
  if (memory_region_register_iommu_notifier(region, notifier, 0) == 0)
    array = g_array_set_size(array, array->len);
}

void failed_registration_then_growth(MemoryRegion *region, GArray *array) {
  TCGIOMMUNotifier *entries = (TCGIOMMUNotifier *)array->data;
  IOMMUNotifier *notifier = &entries[0].notifier;
  iommu_notifier_init(notifier, notify, 1, 0, 4095, 0);
  if (memory_region_register_iommu_notifier(region, notifier, 0) != 0)
    array = g_array_set_size(array, array->len + 1);
}

void unregistered_then_growth(MemoryRegion *region, GArray *array) {
  TCGIOMMUNotifier *entries = (TCGIOMMUNotifier *)array->data;
  IOMMUNotifier *notifier = &entries[0].notifier;
  iommu_notifier_init(notifier, notify, 1, 0, 4095, 0);
  if (memory_region_register_iommu_notifier(region, notifier, 0) == 0) {
    memory_region_unregister_iommu_notifier(region, notifier);
    array = g_array_set_size(array, array->len + 1);
  }
}

void different_array_grows(MemoryRegion *region, GArray *owner,
                           GArray *other) {
  TCGIOMMUNotifier *entries = (TCGIOMMUNotifier *)owner->data;
  IOMMUNotifier *notifier = &entries[0].notifier;
  iommu_notifier_init(notifier, notify, 1, 0, 4095, 0);
  if (memory_region_register_iommu_notifier(region, notifier, 0) == 0)
    other = g_array_set_size(other, other->len + 1);
}

void shrinking_inline_array(MemoryRegion *region, GArray *array) {
  TCGIOMMUNotifier *entries = (TCGIOMMUNotifier *)array->data;
  IOMMUNotifier *notifier = &entries[0].notifier;
  iommu_notifier_init(notifier, notify, 1, 0, 4095, 0);
  if (memory_region_register_iommu_notifier(region, notifier, 0) == 0 &&
      array->len > 0)
    array = g_array_set_size(array, array->len - 1);
}

/* Different C identifier with the same linker symbol is not modeled. */
void *g_array_set_size_wrong(void *array, guint length)
    __asm__("g_array_set_size");

void wrong_signature_is_not_modeled(MemoryRegion *region,
                                    IOMMUNotifier *notifier, void *array) {
  iommu_notifier_init(notifier, notify, 1, 0, 4095, 0);
  if (memory_region_register_iommu_notifier(region, notifier, 0) == 0)
    array = g_array_set_size_wrong(array, 2);
}
