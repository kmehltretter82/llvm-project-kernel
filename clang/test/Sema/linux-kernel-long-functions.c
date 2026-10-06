// The dataflow checks in a long function.  The CFG lists its blocks from the
// exit to the entry, and a dataflow that visits them in that order moves a
// fact by one block in each pass.  With a bound on the passes it never saw
// the end of a function like these, and where a short path and a long one
// meet it reported what held on the short one as holding on every path.
//
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wlinux-kernel \
// RUN:   -Wno-conditional-uninitialized -Wlinux-kernel-missing-error-code \
// RUN:   -Wlinux-kernel-deref-before-check -Wlinux-kernel-use-after-free \
// RUN:   -Wlinux-kernel-duplicate-check -Wlinux-kernel-experimental \
// RUN:   -flinux-kernel-experimental=all -verify %s
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wall -verify=wall %s

// wall-no-diagnostics

typedef _Bool bool;
typedef unsigned long size_t;
#define NULL ((void *)0)
#define ENOMEM 12
#define ENODEV 19
#define offsetof(TYPE, MEMBER) __builtin_offsetof(TYPE, MEMBER)
#define container_of(ptr, type, member) ({ \
  void *__mptr = (void *)(ptr); \
  ((type *)(__mptr - offsetof(type, member))); })

void *kmalloc(size_t size, unsigned int flags);
void *kzalloc(size_t size, unsigned int flags);
void kfree(const void *p);
int step(int n);
int put(int n);

struct list {
  struct list *next;
};

struct dev {
  int a;
  void *p;
  struct list node;
};

struct blob {
  int len;
  int data[] __attribute__((counted_by(len)));
};

struct list *first(struct dev *d);

// Two blocks for each step: the call with its test, and the way out.
#define STEP(n) ret = step(n); if (ret) goto out;
#define STEP4(n) STEP(n) STEP(n) STEP(n) STEP(n)
#define STEP16(n) STEP4(n) STEP4(n) STEP4(n) STEP4(n)
#define STEP64(n) STEP16(n) STEP16(n) STEP16(n) STEP16(n)

// One block for each operand.
#define PUT4(n) put(n) || put(n) || put(n) || put(n)
#define PUT16(n) PUT4(n) || PUT4(n) || PUT4(n) || PUT4(n)
#define PUT64(n) PUT16(n) || PUT16(n) || PUT16(n) || PUT16(n)

// ---------------------------------------------------------------------------
// What comes after a long stretch of code is checked like the rest.

int late_error_code(struct dev *d) {
  int ret;
  void *p;

  STEP64(1)
  STEP64(2)
  p = kmalloc(8, 0);
  if (!p) // expected-warning {{'ret' is zero when this failure path leaves, so the function returns success}}
    goto out;
  d->p = p;
  return 0;
out:
  return ret; // expected-note {{'ret' is returned here}}
}

int late_deref_before_check(struct dev *d) {
  int ret;

  STEP64(1)
  STEP64(2)
  d->a = 1; // expected-note {{'d' is dereferenced here}}
  if (!d) // expected-warning {{'d' is tested for NULL here, but every path to this test has dereferenced it}}
    return -ENODEV;
  return 0;
out:
  return ret;
}

int late_duplicate_check(struct dev *d) {
  int ret;

  STEP64(1)
  STEP64(2)
  if (!d) // expected-note {{previous test is here}}
    return -ENODEV;
  ret = step(0);
  if (d) // expected-warning {{'d' is always nonzero here: every path has tested it and it has not changed since}}
    d->a = ret;
out:
  return ret;
}

int late_use_after_free(void) {
  int *p = kmalloc(sizeof(*p), 0);
  int ret;

  if (!p)
    return -ENOMEM;
  STEP64(1)
  STEP64(2)
  kfree(p); // expected-note {{freed here}}
  return *p; // expected-warning {{'p' is dereferenced here, and every path to this point has freed it}}
out:
  kfree(p);
  return ret;
}

int late_counter(const int *src, int n) {
  struct blob *b;
  int ret;

  STEP64(1)
  STEP64(2)
  b = kzalloc(sizeof(*b) + n * sizeof(int), 0); // expected-note {{the object is allocated here}}
  if (!b)
    return -ENOMEM;
  b->data[0] = src[0]; // expected-warning {{flexible array 'data' is used before its counter 'len' is set}}
  b->len = n; // expected-note {{'len' is set here}}
  ret = b->data[0];
  kfree(b);
out:
  return ret;
}

int late_container_of(struct dev *d) {
  struct dev *other;
  int ret;

  STEP64(1)
  STEP64(2)
  other = container_of(first(d), struct dev, node); // expected-note {{'other' gets its value here}}
  if (!other)
// expected-warning@-1 {{'other' is tested for NULL, but it comes from container_of() with the member at offset 16, so it is not NULL even if the pointer it was computed from is (experimental check 'container-of-null')}}
    return -ENODEV;
  return other->a;
out:
  return ret;
}

static int read_reg(struct dev *d, int *val) {
  if (!d->a)
    return -ENODEV; // expected-note {{'read_reg' returns here without having written through 'val'}}
  *val = d->a;
  return 0;
}

int late_output(struct dev *d) {
  int ret, val;

  STEP64(1)
  STEP64(2)
  read_reg(d, &val); // expected-note {{the address of 'val' is passed to 'read_reg' here}}
  return val; // expected-warning {{'val' is read here, but 'read_reg' does not write to it when it fails, and the result of the call is not tested (experimental check 'uninit-output')}}
out:
  return ret;
}

// ---------------------------------------------------------------------------
// Where a short path and a long one meet, a fact has to hold on both.

// 's' is false on the short way to the second test and true on the long one.
int both_ways_tested(bool s) {
  if (s && (PUT64(1) || PUT64(2)))
    goto fail;
  if (!s && put(0))
    goto fail;
  return 0;
fail:
  return -1;
}

// Only the short way has dereferenced 'd'.
int both_ways_dereferenced(struct dev *d, bool s) {
  int ret = 0;

  if (!s) {
    d->a = 1;
  } else {
    STEP64(1)
    STEP64(2)
  }
  if (!d)
    return -ENODEV;
out:
  return ret;
}

// Only the short way has freed 'p'.
int both_ways_freed(bool s) {
  int *p = kmalloc(sizeof(*p), 0);
  int ret = 0;

  if (!p)
    return -ENOMEM;
  *p = 0;
  if (!s) {
    kfree(p);
  } else {
    STEP64(1)
    STEP64(2)
  }
  if (s) {
    ret = *p;
    kfree(p);
  }
  return ret;
out:
  kfree(p);
  return ret;
}

// Only the short way has left 'val' alone.
int both_ways_written(struct dev *d, bool s) {
  int ret = 0, val;

  if (s) {
    STEP64(1)
    STEP64(2)
    val = 1;
  }
  if (s)
    ret = val;
out:
  return ret;
}
