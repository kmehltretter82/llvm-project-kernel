// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.linux.LockBalance \
// RUN:   -verify %s
//
// Together with the other checker that follows the same locks.
// RUN: %clang_analyze_cc1 \
// RUN:   -analyzer-checker=core,alpha.linux.LockBalance,alpha.linux.AtomicSleep \
// RUN:   -verify %s

#define EINVAL 22
#define EBUSY 16
#define EINTR 4

typedef struct raw_spinlock { int v; } raw_spinlock_t;
typedef struct spinlock { struct raw_spinlock rlock; } spinlock_t;
struct mutex { int v; };
struct rw_semaphore { int v; };

void _raw_spin_lock(raw_spinlock_t *lock);
void _raw_spin_unlock(raw_spinlock_t *lock);
int _raw_spin_trylock(raw_spinlock_t *lock);
void mutex_lock(struct mutex *lock);
int mutex_lock_interruptible(struct mutex *lock);
int mutex_trylock(struct mutex *lock);
void mutex_unlock(struct mutex *lock);
void down_read(struct rw_semaphore *sem);
void up_read(struct rw_semaphore *sem);

static inline void spin_lock(spinlock_t *lock) { _raw_spin_lock(&lock->rlock); }
static inline void spin_unlock(spinlock_t *lock) {
  _raw_spin_unlock(&lock->rlock);
}
static inline int spin_trylock(spinlock_t *lock) {
  return _raw_spin_trylock(&lock->rlock);
}

struct dev {
  spinlock_t lock;
  struct mutex mutex;
  struct rw_semaphore sem;
  int state;
};

int prepare(struct dev *d);
void work(struct dev *d);

// The missed unlock on an error path.

int missed_on_error(struct dev *d) {
  int ret;

  mutex_lock(&d->mutex);
  ret = prepare(d);
  if (ret)
    return ret; // expected-warning {{Lock is still held on this failure path, but other paths release it}}
  work(d);
  mutex_unlock(&d->mutex);
  return 0;
}

int missed_on_constant_error(struct dev *d) {
  spin_lock(&d->lock);
  if (d->state < 0)
    return -EINVAL; // expected-warning {{Lock is still held on this failure path, but other paths release it}}
  d->state++;
  spin_unlock(&d->lock);
  return 0;
}

void missed_in_void(struct dev *d) {
  down_read(&d->sem);
  if (!d->state)
    return; // expected-warning {{Lock is still held on this return path, but another path with the same result releases it}}
  work(d);
  up_read(&d->sem);
}

int missed_after_interruptible(struct dev *d) {
  if (mutex_lock_interruptible(&d->mutex))
    return -EINTR;
  if (prepare(d))
    return -EBUSY; // expected-warning {{Lock is still held on this failure path, but other paths release it}}
  mutex_unlock(&d->mutex);
  return 0;
}

// Balanced.

int balanced(struct dev *d) {
  int ret;

  mutex_lock(&d->mutex);
  ret = prepare(d);
  if (ret)
    goto out;
  work(d);
out:
  mutex_unlock(&d->mutex);
  return ret;
}

int balanced_trylock(struct dev *d) {
  if (!spin_trylock(&d->lock))
    return -EBUSY;
  work(d);
  spin_unlock(&d->lock);
  return 0;
}

int balanced_interruptible(struct dev *d) {
  int ret = mutex_lock_interruptible(&d->mutex);

  if (ret)
    return ret;
  work(d);
  mutex_unlock(&d->mutex);
  return 0;
}

// What the function is for.

// Holds the lock where it succeeds, releases it where it fails.
int get_locked(struct dev *d) {
  mutex_lock(&d->mutex);
  if (d->state < 0) {
    mutex_unlock(&d->mutex);
    return -EINVAL;
  }
  return 0;
}

// Named as a lock function.
int dev_lock_and_check(struct dev *d) {
  mutex_lock(&d->mutex);
  if (d->state < 0)
    return -EINVAL;
  if (d->state > 9) {
    mutex_unlock(&d->mutex);
    return -EBUSY;
  }
  return 0;
}

// The caller holds the lock: dropped and retaken here.
int called_locked(struct dev *d) {
  mutex_unlock(&d->mutex);
  work(d);
  mutex_lock(&d->mutex);
  if (d->state < 0)
    return -EINVAL;
  return 0;
}

// A scoped guard: the unlock is a cleanup function.
static inline struct mutex *class_mutex_constructor(struct mutex *l) {
  mutex_lock(l);
  return l;
}

int guarded(struct dev *d) {
  struct mutex *scope = class_mutex_constructor(&d->mutex);

  (void)scope;
  if (d->state < 0)
    return -EINVAL;
  return 0;
}
