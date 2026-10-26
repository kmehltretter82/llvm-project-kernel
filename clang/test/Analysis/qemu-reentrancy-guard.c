// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.ReentrancyGuard \
// RUN:   -analyzer-config alpha.qemu.ReentrancyGuard:ReentrancySummaryManifest=%S/Inputs/qemu-reentrancy-summary-fixture.json \
// RUN:   -verify=enabled %s
// RUN: %clang_analyze_cc1 -triple i386-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.ReentrancyGuard \
// RUN:   -analyzer-config alpha.qemu.ReentrancyGuard:ReentrancySummaryManifest=%S/Inputs/qemu-reentrancy-summary-fixture.json \
// RUN:   -verify=enabled %s
// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.ReentrancyGuard \
// RUN:   -verify=default %s
// RUN: %clang_analyze_cc1 -triple i386-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.ReentrancyGuard \
// RUN:   -verify=default %s

// default-no-diagnostics

typedef _Bool bool;
#define true 1
#define false 0

typedef struct MemReentrancyGuard {
  bool engaged_in_io;
} MemReentrancyGuard;

typedef struct Owner {
  MemReentrancyGuard guard;
} Owner;

typedef struct Held {
  Owner *owner;
  int live;
} Held;

static Owner other_owner;

static void publication_wrapper(Held *held) {
  (void)held;
}

static void nested_publication(Held *held) {
  publication_wrapper(held);
}

static bool engage_guard(Owner *owner) {
  bool previous = owner->guard.engaged_in_io;
  owner->guard.engaged_in_io = true;
  return previous;
}

static void restore_guard(Owner *owner, bool previous) {
  owner->guard.engaged_in_io = previous;
}

static void vulnerable_entry(void *opaque) {
  Held *held = opaque;
  publication_wrapper(held); // enabled-warning {{[qemu.reentrant-self-mmio-publication] external callback 'vulnerable_entry' reaches a guest-targetable publication while its device reentrancy guard is not engaged}}
  held->live++;
}

/* The manifest-bound publication is not a direct edge from this entry. */
static void inlined_only_entry(void *opaque) {
  Held *held = opaque;
  nested_publication(held);
  held->live++;
}

static void direct_guarded_entry(void *opaque) {
  Held *held = opaque;
  held->owner->guard.engaged_in_io = true;
  publication_wrapper(held);
  held->live++;
  held->owner->guard.engaged_in_io = false;
}

static void direct_alias_guarded_entry(void *opaque) {
  Held *held = opaque;
  MemReentrancyGuard *guard = &held->owner->guard;
  guard->engaged_in_io = true;
  publication_wrapper(held);
  held->live++;
  guard->engaged_in_io = false;
}

static void helper_guarded_entry(void *opaque) {
  Held *held = opaque;
  bool previous = engage_guard(held->owner);
  publication_wrapper(held);
  held->live++;
  restore_guard(held->owner, previous);
}

static void previous_true_guarded_entry(void *opaque) {
  Held *held = opaque;
  held->owner->guard.engaged_in_io = true;
  bool previous = engage_guard(held->owner);
  restore_guard(held->owner, previous);
  publication_wrapper(held);
  held->live++;
}

static void nested_helper_guarded_entry(void *opaque) {
  Held *held = opaque;
  bool outer_previous = engage_guard(held->owner);
  bool inner_previous = engage_guard(held->owner);
  restore_guard(held->owner, inner_previous);
  publication_wrapper(held);
  held->live++;
  restore_guard(held->owner, outer_previous);
}

static void different_owner_guard_entry(void *opaque) {
  Held *held = opaque;
  other_owner.guard.engaged_in_io = true;
  publication_wrapper(held); // enabled-warning {{[qemu.reentrant-self-mmio-publication] external callback 'different_owner_guard_entry' reaches a guest-targetable publication while its device reentrancy guard is not engaged}}
  held->live++;
  other_owner.guard.engaged_in_io = false;
}

static void guard_after_publication_entry(void *opaque) {
  Held *held = opaque;
  publication_wrapper(held); // enabled-warning {{[qemu.reentrant-self-mmio-publication] external callback 'guard_after_publication_entry' reaches a guest-targetable publication while its device reentrancy guard is not engaged}}
  held->owner->guard.engaged_in_io = true;
  held->live++;
  held->owner->guard.engaged_in_io = false;
}

static void restored_before_publication_entry(void *opaque) {
  Held *held = opaque;
  bool previous = engage_guard(held->owner);
  restore_guard(held->owner, previous);
  publication_wrapper(held); // enabled-warning {{[qemu.reentrant-self-mmio-publication] external callback 'restored_before_publication_entry' reaches a guest-targetable publication while its device reentrancy guard is not engaged}}
  held->live++;
}

/* No sealed post-publication-use witness: deliberately absent from manifest. */
static void no_post_use_entry(void *opaque) {
  Held *held = opaque;
  publication_wrapper(held);
}

/* DMA publication exists, but its target cannot reach this device's MMIO. */
static void non_self_targetable_entry(void *opaque) {
  Held *held = opaque;
  publication_wrapper(held);
  held->live++;
}

/* Self-MMIO exists, but no reentrant handler can free the held object. */
static void no_reentrant_free_entry(void *opaque) {
  Held *held = opaque;
  publication_wrapper(held);
  held->live++;
}

/* Not registered by the sealed summary: deliberately absent from manifest. */
static void unregistered_entry(void *opaque) {
  Held *held = opaque;
  publication_wrapper(held);
  held->live++;
}
