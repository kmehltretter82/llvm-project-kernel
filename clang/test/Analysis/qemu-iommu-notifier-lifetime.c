// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.qemu.IOMMUNotifierLifetime \
// RUN:   -analyzer-config ipa=inlining -verify %s

typedef unsigned long long hwaddr;
typedef unsigned IOMMUNotifierFlag;
typedef struct Error Error;
typedef struct MemoryRegion {
  struct MemoryRegion *alias;
  int value;
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

typedef struct Owner {
  int prefix;
  IOMMUNotifier primary;
  IOMMUNotifier secondary;
} Owner;

void iommu_notifier_init(IOMMUNotifier *n, IOMMUNotify fn,
                         IOMMUNotifierFlag flags, hwaddr start, hwaddr end,
                         int iommu_idx);
int memory_region_register_iommu_notifier(MemoryRegion *mr,
                                           IOMMUNotifier *n, Error **errp);
void memory_region_unregister_iommu_notifier(MemoryRegion *mr,
                                              IOMMUNotifier *n);
void g_free(void *pointer);

static void notify(IOMMUNotifier *notifier, IOMMUTLBEntry *entry) {}

void active_owner_free(MemoryRegion *mr, Owner *owner) {
  iommu_notifier_init(&owner->primary, notify, 1, 0, 4095, 0);
  // expected-note@+1 {{IOMMU notifier registered here}}
  if (memory_region_register_iommu_notifier(mr, &owner->primary, 0) == 0)
    g_free(owner); // expected-warning {{Object containing an active IOMMU notifier is released before the notifier is unregistered}}
}

void active_opaque_free(MemoryRegion *mr, Owner *owner, void *opaque) {
  iommu_notifier_init(&owner->primary, notify, 1, 0, 4095, 0);
  owner->primary.opaque = opaque;
  // expected-note@+1 {{IOMMU notifier registered here}}
  if (memory_region_register_iommu_notifier(mr, &owner->primary, 0) == 0)
    g_free(opaque); // expected-warning {{IOMMU notifier opaque object is released while its callback remains registered}}
}

void opaque_set_before_init(MemoryRegion *mr, Owner *owner, void *opaque) {
  owner->primary.opaque = opaque;
  iommu_notifier_init(&owner->primary, notify, 1, 0, 4095, 0);
  // expected-note@+1 {{IOMMU notifier registered here}}
  if (memory_region_register_iommu_notifier(mr, &owner->primary, 0) == 0)
    g_free(opaque); // expected-warning {{IOMMU notifier opaque object is released while its callback remains registered}}
}

void standalone_notifier_opaque(MemoryRegion *mr, IOMMUNotifier *notifier,
                                void *opaque) {
  notifier->opaque = opaque;
  iommu_notifier_init(notifier, notify, 1, 0, 4095, 0);
  // expected-note@+1 {{IOMMU notifier registered here}}
  if (memory_region_register_iommu_notifier(mr, notifier, 0) == 0)
    g_free(opaque); // expected-warning {{IOMMU notifier opaque object is released while its callback remains registered}}
}

void duplicate_registration(MemoryRegion *mr, Owner *owner) {
  iommu_notifier_init(&owner->primary, notify, 1, 0, 4095, 0);
  // expected-note@+1 {{IOMMU notifier first registered here}}
  if (memory_region_register_iommu_notifier(mr, &owner->primary, 0) == 0)
    if (memory_region_register_iommu_notifier(mr, &owner->primary, 0) == 0) // expected-warning {{IOMMU notifier is registered twice with the same memory region}}
      return;
}

void duplicate_registration_even_if_second_call_fails(MemoryRegion *mr,
                                                       Owner *owner) {
  iommu_notifier_init(&owner->primary, notify, 1, 0, 4095, 0);
  // expected-note@+1 {{IOMMU notifier first registered here}}
  if (memory_region_register_iommu_notifier(mr, &owner->primary, 0) == 0)
    if (memory_region_register_iommu_notifier(mr, &owner->primary, 0) != 0) // expected-warning {{IOMMU notifier is registered twice with the same memory region}}
      return;
}

void duplicate_registration_through_alias(Owner *owner) {
  MemoryRegion target = {0};
  MemoryRegion alias = {&target, 0};
  iommu_notifier_init(&owner->primary, notify, 1, 0, 4095, 0);
  // expected-note@+1 {{IOMMU notifier first registered here}}
  if (memory_region_register_iommu_notifier(&alias, &owner->primary, 0) == 0)
    if (memory_region_register_iommu_notifier(&target, &owner->primary, 0) == 0) // expected-warning {{IOMMU notifier is registered twice with the same memory region}}
      return;
}

void duplicate_registration_through_symbolic_alias(MemoryRegion *alias,
                                                    Owner *owner) {
  MemoryRegion target = {0};
  alias->alias = &target;
  iommu_notifier_init(&owner->primary, notify, 1, 0, 4095, 0);
  // expected-note@+1 {{IOMMU notifier first registered here}}
  if (memory_region_register_iommu_notifier(alias, &owner->primary, 0) == 0)
    if (memory_region_register_iommu_notifier(&target, &owner->primary, 0) == 0) // expected-warning {{IOMMU notifier is registered twice with the same memory region}}
      return;
}

void duplicate_registration_on_another_region(Owner *owner) {
  MemoryRegion first = {0};
  MemoryRegion second = {0};
  iommu_notifier_init(&owner->primary, notify, 1, 0, 4095, 0);
  // expected-note@+1 {{IOMMU notifier first registered here}}
  if (memory_region_register_iommu_notifier(&first, &owner->primary, 0) == 0)
    if (memory_region_register_iommu_notifier(&second, &owner->primary, 0) == 0) // expected-warning {{IOMMU notifier is registered again while it is already active}}
      return;
}

void reinitialize_active_notifier(MemoryRegion *mr, Owner *owner) {
  iommu_notifier_init(&owner->primary, notify, 1, 0, 4095, 0);
  // expected-note@+1 {{IOMMU notifier registered here}}
  if (memory_region_register_iommu_notifier(mr, &owner->primary, 0) == 0) {
    iommu_notifier_init(&owner->primary, notify, 2, 0, 8191, 1); // expected-warning {{Active IOMMU notifier is reinitialized before it is unregistered}}
    g_free(owner);
  }
}

void mismatched_unregister(Owner *owner) {
  MemoryRegion mr1 = {0};
  MemoryRegion mr2 = {0};
  iommu_notifier_init(&owner->primary, notify, 1, 0, 4095, 0);
  // expected-note@+1 {{IOMMU notifier registered here}}
  if (memory_region_register_iommu_notifier(&mr1, &owner->primary, 0) == 0) {
    memory_region_unregister_iommu_notifier(&mr2, &owner->primary); // expected-warning {{IOMMU notifier is unregistered from a different memory region}}
    g_free(owner);
  }
}

void initialize_without_register(Owner *owner) {
  iommu_notifier_init(&owner->primary, notify, 1, 0, 4095, 0);
  g_free(owner);
}

void failed_register_then_free(MemoryRegion *mr, Owner *owner) {
  iommu_notifier_init(&owner->primary, notify, 1, 0, 4095, 0);
  if (memory_region_register_iommu_notifier(mr, &owner->primary, 0) != 0)
    g_free(owner);
}

void exact_unregister_then_free(MemoryRegion *mr, Owner *owner) {
  iommu_notifier_init(&owner->primary, notify, 1, 0, 4095, 0);
  if (memory_region_register_iommu_notifier(mr, &owner->primary, 0) == 0) {
    memory_region_unregister_iommu_notifier(mr, &owner->primary);
    g_free(owner);
  }
}

void unregister_mutate_reregister(MemoryRegion *mr, Owner *owner) {
  iommu_notifier_init(&owner->primary, notify, 1, 0, 4095, 0);
  if (memory_region_register_iommu_notifier(mr, &owner->primary, 0) != 0)
    return;
  memory_region_unregister_iommu_notifier(mr, &owner->primary);
  owner->primary.notifier_flags = 2;
  if (memory_region_register_iommu_notifier(mr, &owner->primary, 0) != 0)
    return;
  memory_region_unregister_iommu_notifier(mr, &owner->primary);
  g_free(owner);
}

void two_independent_notifiers(MemoryRegion *mr, Owner *owner) {
  iommu_notifier_init(&owner->primary, notify, 1, 0, 4095, 0);
  iommu_notifier_init(&owner->secondary, notify, 1, 0, 4095, 0);
  if (memory_region_register_iommu_notifier(mr, &owner->primary, 0) != 0)
    return;
  if (memory_region_register_iommu_notifier(mr, &owner->secondary, 0) != 0)
    return;
  memory_region_unregister_iommu_notifier(mr, &owner->primary);
  memory_region_unregister_iommu_notifier(mr, &owner->secondary);
  g_free(owner);
}

void reuse_on_another_region(MemoryRegion *mr1, MemoryRegion *mr2,
                             Owner *owner) {
  iommu_notifier_init(&owner->primary, notify, 1, 0, 4095, 0);
  if (memory_region_register_iommu_notifier(mr1, &owner->primary, 0) != 0)
    return;
  memory_region_unregister_iommu_notifier(mr1, &owner->primary);
  if (memory_region_register_iommu_notifier(mr2, &owner->primary, 0) != 0)
    return;
  memory_region_unregister_iommu_notifier(mr2, &owner->primary);
  g_free(owner);
}

void unknown_result_is_split(MemoryRegion *mr, Owner *owner) {
  iommu_notifier_init(&owner->primary, notify, 1, 0, 4095, 0);
  // expected-note@+1 {{IOMMU notifier registered here}}
  int result = memory_region_register_iommu_notifier(mr, &owner->primary, 0);
  if (result == 0) {
    g_free(owner); // expected-warning {{Object containing an active IOMMU notifier is released before the notifier is unregistered}}
    return;
  }
  g_free(owner);
}

void actual_alias_regions_match(Owner *owner) {
  MemoryRegion target = {0};
  MemoryRegion alias = {&target, 0};
  iommu_notifier_init(&owner->primary, notify, 1, 0, 4095, 0);
  if (memory_region_register_iommu_notifier(&alias, &owner->primary, 0) == 0) {
    memory_region_unregister_iommu_notifier(&target, &owner->primary);
    g_free(owner);
  }
}

void retargeted_alias_is_a_mismatch(Owner *owner) {
  MemoryRegion first = {0};
  MemoryRegion second = {0};
  MemoryRegion alias = {&first, 0};
  iommu_notifier_init(&owner->primary, notify, 1, 0, 4095, 0);
  // expected-note@+1 {{IOMMU notifier registered here}}
  if (memory_region_register_iommu_notifier(&alias, &owner->primary, 0) == 0) {
    alias.alias = &second;
    memory_region_unregister_iommu_notifier(&alias, &owner->primary); // expected-warning {{IOMMU notifier is unregistered from a different memory region}}
    g_free(owner);
  }
}

void possibly_aliasing_regions_do_not_warn(MemoryRegion *mr1,
                                            MemoryRegion *mr2, Owner *owner) {
  iommu_notifier_init(&owner->primary, notify, 1, 0, 4095, 0);
  if (memory_region_register_iommu_notifier(mr1, &owner->primary, 0) == 0) {
    memory_region_unregister_iommu_notifier(mr2, &owner->primary);
    g_free(owner);
  }
}

void possibly_aliasing_notifier_retires_definite_state(MemoryRegion *mr,
                                                       Owner *owner,
                                                       IOMMUNotifier *maybe) {
  iommu_notifier_init(&owner->primary, notify, 1, 0, 4095, 0);
  if (memory_region_register_iommu_notifier(mr, &owner->primary, 0) == 0) {
    memory_region_unregister_iommu_notifier(mr, maybe);
    g_free(owner);
  }
}

static int register_wrapper(MemoryRegion *mr, IOMMUNotifier *notifier) {
  // expected-note@+1 {{IOMMU notifier registered here}}
  return memory_region_register_iommu_notifier(mr, notifier, 0);
}

void wrapper_records_once(MemoryRegion *mr, Owner *owner) {
  iommu_notifier_init(&owner->primary, notify, 1, 0, 4095, 0);
  if (register_wrapper(mr, &owner->primary) == 0)
    g_free(owner); // expected-warning {{Object containing an active IOMMU notifier is released before the notifier is unregistered}}
}

void opaque_replaced_while_active(MemoryRegion *mr, Owner *owner,
                                  void *old_opaque, void *new_opaque) {
  owner->primary.opaque = old_opaque;
  iommu_notifier_init(&owner->primary, notify, 1, 0, 4095, 0);
  // expected-note@+1 {{IOMMU notifier registered here}}
  if (memory_region_register_iommu_notifier(mr, &owner->primary, 0) == 0) {
    owner->primary.opaque = new_opaque;
    g_free(old_opaque);
    g_free(new_opaque); // expected-warning {{IOMMU notifier opaque object is released while its callback remains registered}}
  }
}

void opaque_cleared_while_active(MemoryRegion *mr, Owner *owner,
                                 void *opaque) {
  owner->primary.opaque = opaque;
  iommu_notifier_init(&owner->primary, notify, 1, 0, 4095, 0);
  if (memory_region_register_iommu_notifier(mr, &owner->primary, 0) == 0) {
    owner->primary.opaque = 0;
    g_free(opaque);
    memory_region_unregister_iommu_notifier(mr, &owner->primary);
    g_free(owner);
  }
}

void clobber_notifier(IOMMUNotifier *notifier);
void clobber_region(MemoryRegion *region);

void unknown_clobber_drops_opaque_precision(MemoryRegion *mr, Owner *owner,
                                            void *opaque) {
  owner->primary.opaque = opaque;
  iommu_notifier_init(&owner->primary, notify, 1, 0, 4095, 0);
  if (memory_region_register_iommu_notifier(mr, &owner->primary, 0) == 0) {
    clobber_notifier(&owner->primary);
    g_free(opaque);
    memory_region_unregister_iommu_notifier(mr, &owner->primary);
    g_free(owner);
  }
}

void precise_opaque_write_after_unknown_clobber(MemoryRegion *mr, Owner *owner,
                                                void *opaque) {
  iommu_notifier_init(&owner->primary, notify, 1, 0, 4095, 0);
  // expected-note@+1 {{IOMMU notifier registered here}}
  if (memory_region_register_iommu_notifier(mr, &owner->primary, 0) == 0) {
    clobber_notifier(&owner->primary);
    owner->primary.opaque = opaque;
    g_free(opaque); // expected-warning {{IOMMU notifier opaque object is released while its callback remains registered}}
  }
}

void unknown_region_clobber_drops_alias_precision(Owner *owner) {
  MemoryRegion first = {0};
  MemoryRegion alias = {&first, 0};
  iommu_notifier_init(&owner->primary, notify, 1, 0, 4095, 0);
  if (memory_region_register_iommu_notifier(&alias, &owner->primary, 0) == 0) {
    clobber_region(&alias);
    memory_region_unregister_iommu_notifier(&alias, &owner->primary);
    g_free(owner);
  }
}

void mutated_unresolved_alias_still_rejects_active_notifier(
    MemoryRegion *unknown, Owner *owner) {
  MemoryRegion second = {0};
  MemoryRegion alias = {unknown, 0};
  iommu_notifier_init(&owner->primary, notify, 1, 0, 4095, 0);
  // expected-note@+1 {{IOMMU notifier first registered here}}
  if (memory_region_register_iommu_notifier(&alias, &owner->primary, 0) == 0) {
    alias.alias = &second;
    (void)memory_region_register_iommu_notifier(&alias, &owner->primary, 0); // expected-warning {{IOMMU notifier is registered again while it is already active}}
  }
}

void uninitialized_registration_is_not_assumed(Owner *owner,
                                                MemoryRegion *mr) {
  if (memory_region_register_iommu_notifier(mr, &owner->primary, 0) == 0)
    g_free(owner);
}
