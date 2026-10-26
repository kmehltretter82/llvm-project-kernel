// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.ReentrancyGuard \
// RUN:   -analyzer-config alpha.qemu.ReentrancyGuard:ReentrancySummaryManifest=%S/Inputs/qemu-reentrancy-indirect-dispatch.json \
// RUN:   -verify=enabled %s
// RUN: %clang_analyze_cc1 -triple i386-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.ReentrancyGuard \
// RUN:   -analyzer-config alpha.qemu.ReentrancyGuard:ReentrancySummaryManifest=%S/Inputs/qemu-reentrancy-indirect-dispatch.json \
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

typedef struct Held Held;
typedef void (*PublishFn)(Held *);

struct Held {
  Owner *owner;
  PublishFn runtime_publish;
  int live;
};

typedef struct PublishOps {
  PublishFn publish;
} PublishOps;

static void publication_wrapper(Held *held) {
  (void)held;
}

static void other_wrapper(Held *held) {
  (void)held;
}

static const PublishOps publication_ops = { publication_wrapper };
static const PublishOps other_ops = { other_wrapper };

static void local_pointer_entry(void *opaque) {
  Held *held = opaque;
  PublishFn publish = publication_wrapper;
  publish(held); // enabled-warning {{[qemu.reentrant-self-mmio-publication] external callback 'local_pointer_entry' reaches a guest-targetable publication while its device reentrancy guard is not engaged}}
  held->live++;
}

static void ops_pointer_entry(void *opaque) {
  Held *held = opaque;
  publication_ops.publish(held); // enabled-warning {{[qemu.reentrant-self-mmio-publication] external callback 'ops_pointer_entry' reaches a guest-targetable publication while its device reentrancy guard is not engaged}}
  held->live++;
}

static void guarded_ops_pointer_entry(void *opaque) {
  Held *held = opaque;
  held->owner->guard.engaged_in_io = true;
  publication_ops.publish(held);
  held->live++;
  held->owner->guard.engaged_in_io = false;
}

static void wrong_ops_pointer_entry(void *opaque) {
  Held *held = opaque;
  other_ops.publish(held);
  held->live++;
}

static void branch_selected_pointer_entry(void *opaque) {
  Held *held = opaque;
  PublishFn publish =
      held->live ? publication_wrapper : other_wrapper;
  publish(held); // enabled-warning {{[qemu.reentrant-self-mmio-publication] external callback 'branch_selected_pointer_entry' reaches a guest-targetable publication while its device reentrancy guard is not engaged}}
  held->live++;
}

/* An unresolved function pointer is not enough to claim publication. */
static void unresolved_pointer_entry(void *opaque) {
  Held *held = opaque;
  held->runtime_publish(held);
  held->live++;
}
