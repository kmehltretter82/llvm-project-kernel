// The options of alpha.linux.KernelModel, and functions that the contracts
// file says sleep.
//
// RUN: %clang_analyze_cc1 \
// RUN:   -analyzer-checker=core,alpha.linux.AtomicSleep,debug.ExprInspection \
// RUN:   -verify=expected,all %s
// RUN: %clang_analyze_cc1 \
// RUN:   -analyzer-checker=core,alpha.linux.AtomicSleep,debug.ExprInspection \
// RUN:   -analyzer-config alpha.linux.KernelModel:SkipIrrelevant=true \
// RUN:   -analyzer-config alpha.linux.KernelModel:LikelyStaticBranches=true \
// RUN:   -verify=expected,fast %s
//
// RUN: rm -rf %t && mkdir %t
// RUN: echo "sleeps	remote_sleeper" > %t/contracts
// RUN: %clang_analyze_cc1 \
// RUN:   -analyzer-checker=core,alpha.linux.AtomicSleep,debug.ExprInspection \
// RUN:   -flinux-kernel-contracts=%t/contracts \
// RUN:   -verify=expected,all,contract %s

void clang_analyzer_warnIfReached(void);

typedef struct raw_spinlock { int v; } raw_spinlock_t;
typedef struct spinlock { struct raw_spinlock rlock; } spinlock_t;

void _raw_spin_lock(raw_spinlock_t *lock);
void _raw_spin_unlock(raw_spinlock_t *lock);
void msleep(unsigned int msecs);
void remote_sleeper(void *arg);
void remote_other(void *arg);

static inline void spin_lock(spinlock_t *lock) { _raw_spin_lock(&lock->rlock); }
static inline void spin_unlock(spinlock_t *lock) {
  _raw_spin_unlock(&lock->rlock);
}

struct static_key { int enabled; };

static inline __attribute__((always_inline)) _Bool
arch_static_branch(struct static_key *const key, const _Bool branch) {
  asm goto("nop" : : "i"(key), "i"(branch) : : l_yes);
  return 0;
l_yes:
  return 1;
}

struct dev {
  spinlock_t lock;
  int flags;
};

struct static_key trace_key;

// Nothing in here that a checker could report on.
void irrelevant(struct dev *d) {
  d->flags = 1;
  clang_analyzer_warnIfReached(); // all-warning {{REACHABLE}}
}

// A lock: analyzed with or without the option.
void relevant(struct dev *d) {
  spin_lock(&d->lock);
  clang_analyzer_warnIfReached(); // expected-warning {{REACHABLE}}
  msleep(1); // expected-warning {{Call to sleeping function 'msleep' with a spinlock held}}
  spin_unlock(&d->lock);
}

// Taking the lock does not make the analyzer forget the object around it.
void keeps_fields(struct dev *d) {
  if (d->flags != 4)
    return;
  spin_lock(&d->lock);
  if (d->flags != 4)
    clang_analyzer_warnIfReached(); // no-warning
  spin_unlock(&d->lock);
}

// "if (static_branch_unlikely(&key))": not taken with the option.
void static_branch(struct dev *d) {
  spin_lock(&d->lock);
  if (arch_static_branch(&trace_key, 0))
    clang_analyzer_warnIfReached(); // all-warning {{REACHABLE}}
  spin_unlock(&d->lock);
}

// A function of another translation unit that always sleeps.
void calls_remote(struct dev *d) {
  spin_lock(&d->lock);
  remote_other(d);
  remote_sleeper(d); // contract-warning {{Call to 'remote_sleeper' (always sleeps, according to its definition) with a spinlock held}}
  spin_unlock(&d->lock);
}
