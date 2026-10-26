// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.AsyncTeardown \
// RUN:   -analyzer-config alpha.qemu.AsyncTeardown:AsyncTeardownSummaryManifest=%S/Inputs/qemu-async-teardown-summary.json \
// RUN:   -DMISSING_CANCEL -verify=missing %s
// RUN: %clang_analyze_cc1 -triple i386-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.AsyncTeardown \
// RUN:   -analyzer-config alpha.qemu.AsyncTeardown:AsyncTeardownSummaryManifest=%S/Inputs/qemu-async-teardown-summary.json \
// RUN:   -DMISSING_CANCEL -verify=missing %s
// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.AsyncTeardown \
// RUN:   -analyzer-config alpha.qemu.AsyncTeardown:AsyncTeardownSummaryManifest=%S/Inputs/qemu-async-teardown-summary.json \
// RUN:   -DEXACT_CANCEL -verify=exact %s
// RUN: %clang_analyze_cc1 -triple i386-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.AsyncTeardown \
// RUN:   -analyzer-config alpha.qemu.AsyncTeardown:AsyncTeardownSummaryManifest=%S/Inputs/qemu-async-teardown-summary.json \
// RUN:   -DEXACT_CANCEL -verify=exact %s
// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.AsyncTeardown \
// RUN:   -analyzer-config alpha.qemu.AsyncTeardown:AsyncTeardownSummaryManifest=%S/Inputs/qemu-async-teardown-summary.json \
// RUN:   -DWRONG_CALLBACK -verify=wrong-callback %s
// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.AsyncTeardown \
// RUN:   -analyzer-config alpha.qemu.AsyncTeardown:AsyncTeardownSummaryManifest=%S/Inputs/qemu-async-teardown-summary.json \
// RUN:   -DWRONG_OWNER -verify=wrong-owner %s
// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.AsyncTeardown \
// RUN:   -analyzer-config alpha.qemu.AsyncTeardown:AsyncTeardownSummaryManifest=%S/Inputs/qemu-async-teardown-summary.json \
// RUN:   -DCONDITIONAL_CANCEL -verify=conditional %s
// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.AsyncTeardown \
// RUN:   -analyzer-config alpha.qemu.AsyncTeardown:AsyncTeardownSummaryManifest=%S/Inputs/qemu-async-teardown-summary.json \
// RUN:   -DLATE_CANCEL -verify=late %s
// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.AsyncTeardown \
// RUN:   -analyzer-config alpha.qemu.AsyncTeardown:AsyncTeardownSummaryManifest=%S/Inputs/qemu-async-teardown-summary.json \
// RUN:   -DEARLY_RETURN -verify=early-return %s
// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.AsyncTeardown \
// RUN:   -verify=default %s
// RUN: %clang_analyze_cc1 -triple i386-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.AsyncTeardown \
// RUN:   -verify=default %s
// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.AsyncTeardown \
// RUN:   -analyzer-config alpha.qemu.AsyncTeardown:AsyncTeardownSummaryManifest=%S/Inputs/qemu-async-teardown-incomplete.json \
// RUN:   -verify=incomplete %s
// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.qemu.AsyncTeardown \
// RUN:   -analyzer-config alpha.qemu.AsyncTeardown:AsyncTeardownSummaryManifest=%S/Inputs/qemu-async-teardown-invalid-schedules.json \
// RUN:   -verify=schedule-invalid %s

// default-no-diagnostics
// incomplete-no-diagnostics
// schedule-invalid-no-diagnostics
// exact-no-diagnostics

typedef __SIZE_TYPE__ size_t;

typedef struct Backend Backend;
typedef struct Owner {
  Backend *backend;
  int live;
} Owner;

typedef void EntropyCallback(void *, const void *, size_t);

void async_request(Backend *, size_t, EntropyCallback *, void *);
void async_cancel(Backend *, EntropyCallback *, const void *);
void release_owner(Owner *);

static void completion(void *opaque, const void *buffer, size_t size)
{
  Owner *owner = opaque;
  owner->live += buffer != 0 && size != 0;
}

static void other_completion(void *opaque, const void *buffer, size_t size)
{
  Owner *owner = opaque;
  owner->live -= buffer != 0 && size != 0;
}

static void queue_request(Owner *owner)
{
  async_request(owner->backend, 16, completion, owner);
}

void teardown(Owner *owner, Owner *other, int cancel)
{ // missing-warning {{[qemu.async-teardown-missing-cancel] teardown 'teardown' can release callback owner 'owner' while a queued request can later invoke 'completion'; no exact 'async_cancel' call cancels backend member 'backend', callback, and opaque owner tuple (sealed schedule 'queued-callback-owner-teardown')}} wrong-callback-warning {{[qemu.async-teardown-missing-cancel] teardown 'teardown' can release callback owner 'owner' while a queued request can later invoke 'completion'; no exact 'async_cancel' call cancels backend member 'backend', callback, and opaque owner tuple (sealed schedule 'queued-callback-owner-teardown')}} wrong-owner-warning {{[qemu.async-teardown-missing-cancel] teardown 'teardown' can release callback owner 'owner' while a queued request can later invoke 'completion'; no exact 'async_cancel' call cancels backend member 'backend', callback, and opaque owner tuple (sealed schedule 'queued-callback-owner-teardown')}} conditional-warning {{[qemu.async-teardown-missing-cancel] teardown 'teardown' can release callback owner 'owner' while a queued request can later invoke 'completion'; no exact 'async_cancel' call cancels backend member 'backend', callback, and opaque owner tuple (sealed schedule 'queued-callback-owner-teardown')}} late-warning {{[qemu.async-teardown-missing-cancel] teardown 'teardown' can release callback owner 'owner' while a queued request can later invoke 'completion'; no exact 'async_cancel' call cancels backend member 'backend', callback, and opaque owner tuple (sealed schedule 'queued-callback-owner-teardown')}} early-return-warning {{[qemu.async-teardown-missing-cancel] teardown 'teardown' can release callback owner 'owner' while a queued request can later invoke 'completion'; no exact 'async_cancel' call cancels backend member 'backend', callback, and opaque owner tuple (sealed schedule 'queued-callback-owner-teardown')}}
#if defined(MISSING_CANCEL)
#elif defined(EXACT_CANCEL)
  async_cancel(owner->backend, completion, owner);
#elif defined(WRONG_CALLBACK)
  async_cancel(owner->backend, other_completion, owner);
#elif defined(WRONG_OWNER)
  async_cancel(owner->backend, completion, other);
#elif defined(CONDITIONAL_CANCEL)
  if (cancel) {
    async_cancel(owner->backend, completion, owner);
  }
#elif defined(LATE_CANCEL)
  release_owner(owner);
  async_cancel(owner->backend, completion, owner);
  return;
#elif defined(EARLY_RETURN)
  if (!cancel) {
    return;
  }
  async_cancel(owner->backend, completion, owner);
#else
  (void)other;
  (void)cancel;
#endif
  release_owner(owner);
}
