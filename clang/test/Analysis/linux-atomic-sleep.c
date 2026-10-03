// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.linux.AtomicSleep \
// RUN:   -analyzer-output=text -verify %s

typedef unsigned int gfp_t;

enum {
  ___GFP_IO_BIT = 6,
  ___GFP_DIRECT_RECLAIM_BIT = 10,
  ___GFP_KSWAPD_RECLAIM_BIT = 11,
};
#define GFP_ATOMIC ((gfp_t)(1u << ___GFP_KSWAPD_RECLAIM_BIT))
#define GFP_KERNEL                                                            \
  ((gfp_t)((1u << ___GFP_DIRECT_RECLAIM_BIT) |                                \
           (1u << ___GFP_KSWAPD_RECLAIM_BIT) | (1u << ___GFP_IO_BIT)))

typedef struct raw_spinlock { int v; } raw_spinlock_t;
typedef struct spinlock { struct raw_spinlock rlock; } spinlock_t;
struct mutex { int v; };

void _raw_spin_lock(raw_spinlock_t *lock);
void _raw_spin_unlock(raw_spinlock_t *lock);
unsigned long _raw_spin_lock_irqsave(raw_spinlock_t *lock);
void _raw_spin_unlock_irqrestore(raw_spinlock_t *lock, unsigned long flags);
int _raw_spin_trylock(raw_spinlock_t *lock);
void __rcu_read_lock(void);
void __rcu_read_unlock(void);
void preempt_count_add(int val);
void preempt_count_sub(int val);

void __might_sleep(const char *file, int line);
void msleep(unsigned int msecs);
void mutex_lock_nested(struct mutex *lock, unsigned int subclass);
void *__kmalloc_noprof(unsigned long size, gfp_t flags);
void udelay(unsigned long usecs);
void board_unlock_bus(void *board);

static inline void spin_lock(spinlock_t *lock) {
  _raw_spin_lock(&lock->rlock); // expected-note 2 {{Spinlock taken here}}
}
static inline void spin_unlock(spinlock_t *lock) {
  _raw_spin_unlock(&lock->rlock);
}
static inline int spin_trylock(spinlock_t *lock) {
  return _raw_spin_trylock(&lock->rlock); // expected-note {{Spinlock taken here}}
}
static inline void rcu_read_lock(void) {
  __rcu_read_lock(); // expected-note {{RCU read-side critical section entered here}}
}
static inline void rcu_read_unlock(void) { __rcu_read_unlock(); }
#define spin_lock_irqsave(lock, flags)                                        \
  do {                                                                        \
    flags = _raw_spin_lock_irqsave(&(lock)->rlock);                           \
  } while (0)
#define spin_unlock_irqrestore(lock, flags)                                   \
  _raw_spin_unlock_irqrestore(&(lock)->rlock, flags)
#define might_sleep() __might_sleep(__FILE__, __LINE__)
#define mutex_lock(lock) mutex_lock_nested(lock, 0)
#define kmalloc(size, flags) __kmalloc_noprof(size, flags)

struct dev {
  spinlock_t lock;
  struct mutex mutex;
  int busy;
  void *buf;
};

void sleep_under_spinlock(struct dev *d) {
  spin_lock(&d->lock); // expected-note {{Calling 'spin_lock'}}
                       // expected-note@-1 {{Returning from 'spin_lock'}}
  msleep(10); // expected-warning {{Call to sleeping function 'msleep' with a spinlock held}}
              // expected-note@-1 {{Call to sleeping function 'msleep' with a spinlock held}}
  spin_unlock(&d->lock);
}

void sleep_after_unlock(struct dev *d) {
  spin_lock(&d->lock);
  d->busy = 1;
  spin_unlock(&d->lock);
  msleep(10);
}

void delay_under_spinlock(struct dev *d) {
  spin_lock(&d->lock);
  udelay(10);
  spin_unlock(&d->lock);
}

void sleep_on_one_path(struct dev *d, int wait) {
  unsigned long flags;

  spin_lock_irqsave(&d->lock, flags); // expected-note {{Spinlock taken here}}
                                      // expected-note@-1 {{Loop condition is false.  Exiting loop}}
  if (wait) // expected-note {{Assuming 'wait' is not equal to 0}}
            // expected-note@-1 {{Taking true branch}}
    mutex_lock(&d->mutex); // expected-warning {{Call to sleeping function 'mutex_lock_nested' with a spinlock held}}
                           // expected-note@-1 {{Call to sleeping function 'mutex_lock_nested' with a spinlock held}}
  spin_unlock_irqrestore(&d->lock, flags);
}

void alloc_under_spinlock(struct dev *d) {
  spin_lock(&d->lock); // expected-note {{Calling 'spin_lock'}}
                       // expected-note@-1 {{Returning from 'spin_lock'}}
  d->buf = kmalloc(64, GFP_KERNEL); // expected-warning {{Call to '__kmalloc_noprof' with gfp flags that may sleep with a spinlock held}}
                                    // expected-note@-1 {{Call to '__kmalloc_noprof' with gfp flags that may sleep with a spinlock held}}
  spin_unlock(&d->lock);
}

void atomic_alloc_under_spinlock(struct dev *d) {
  spin_lock(&d->lock);
  d->buf = kmalloc(64, GFP_ATOMIC);
  spin_unlock(&d->lock);
}

void unknown_flags_under_spinlock(struct dev *d, gfp_t gfp) {
  spin_lock(&d->lock);
  d->buf = kmalloc(64, gfp);
  spin_unlock(&d->lock);
}

static void helper_that_sleeps(struct dev *d) {
  might_sleep(); // expected-warning {{might_sleep() reached inside an RCU read-side critical section}}
                 // expected-note@-1 {{might_sleep() reached inside an RCU read-side critical section}}
  d->busy = 0;
}

void sleep_in_callee_under_rcu(struct dev *d) {
  rcu_read_lock(); // expected-note {{Calling 'rcu_read_lock'}}
                   // expected-note@-1 {{Returning from 'rcu_read_lock'}}
  helper_that_sleeps(d); // expected-note {{Calling 'helper_that_sleeps'}}
  rcu_read_unlock();
}

void sleep_with_preemption_off(void) {
  preempt_count_add(1); // expected-note {{Preemption disabled here}}
  msleep(1); // expected-warning {{Call to sleeping function 'msleep' with preemption disabled}}
             // expected-note@-1 {{Call to sleeping function 'msleep' with preemption disabled}}
  preempt_count_sub(1);
}

void trylock_failed(struct dev *d) {
  if (!spin_trylock(&d->lock)) {
    msleep(10);
    return;
  }
  d->busy = 1;
  spin_unlock(&d->lock);
}

void trylock_taken(struct dev *d) {
  if (spin_trylock(&d->lock)) { // expected-note {{Calling 'spin_trylock'}}
                                // expected-note@-1 {{Returning from 'spin_trylock'}}
                                // expected-note@-2 {{Taking true branch}}
    msleep(10); // expected-warning {{Call to sleeping function 'msleep' with a spinlock held}}
                // expected-note@-1 {{Call to sleeping function 'msleep' with a spinlock held}}
    spin_unlock(&d->lock);
  }
}

void unlock_helper_elsewhere(struct dev *d) {
  spin_lock(&d->lock);
  board_unlock_bus(d);
  msleep(10);
}

void nested_locks(struct dev *a, struct dev *b) {
  spin_lock(&a->lock);
  spin_lock(&b->lock);
  spin_unlock(&b->lock);
  spin_unlock(&a->lock);
  msleep(10);
}
