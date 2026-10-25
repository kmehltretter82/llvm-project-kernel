// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.qemu.IOMMUNotifierLifetime \
// RUN:   -analyzer-config ipa=none -verify %s
// expected-no-diagnostics

typedef struct MemoryRegion {
  int value;
} MemoryRegion;
typedef struct IOMMUNotifier {
  void *opaque;
} IOMMUNotifier;

/* Deliberate same-name lookalikes with non-QEMU signatures. */
void iommu_notifier_init(IOMMUNotifier *notifier, void *callback, int flags);
int memory_region_register_iommu_notifier(MemoryRegion *region,
                                           IOMMUNotifier *notifier);
void memory_region_unregister_iommu_notifier(IOMMUNotifier *notifier,
                                              MemoryRegion *region);
void g_free(void *pointer);

void wrong_signatures_are_not_modeled(MemoryRegion *region,
                                      IOMMUNotifier *notifier, void *callback) {
  iommu_notifier_init(notifier, callback, 1);
  if (memory_region_register_iommu_notifier(region, notifier) == 0) {
    memory_region_unregister_iommu_notifier(notifier, region);
    g_free(notifier);
  }
}
