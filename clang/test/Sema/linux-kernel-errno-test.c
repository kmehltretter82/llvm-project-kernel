// Kernel error codes are negative.  A variable that a function treats as
// one, and compares with an error number without the minus sign, is
// compared with something that it never is.
//
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wlinux-kernel-experimental \
// RUN:   -flinux-kernel-experimental=positive-errno-test -verify %s
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wall -verify=wall %s

// wall-no-diagnostics

typedef _Bool bool;
#define NULL ((void *)0)
#define EINTR 4
#define EAGAIN 11
#define ENOMEM 12
#define EBUSY 16
#define EDEADLK 35
#define ERESTARTSYS 512
#define EPROBE_DEFER 517
#define unlikely(x) __builtin_expect(!!(x), 0)
#define WARN_ON_ONCE(x) ({ int __w = !!(x); unlikely(__w); })

bool IS_ERR(const void *);
long PTR_ERR(const void *);
void *ERR_PTR(long);
int _printk(const char *fmt, ...);
int pin(void *obj);
int wait(void *obj);
void *lookup(int id);
void close_dev(void *obj);

// ---------------------------------------------------------------------------
// The minus sign is missing.

int among_others(void *obj) {
  int err = pin(obj);

  if (err) {
    if (err != -EINTR && err != ERESTARTSYS && err != -EDEADLK)
// expected-warning@-1 {{'err' is compared with ERESTARTSYS, which is positive, but this function treats 'err' as a kernel error code, and those are negative: '-ERESTARTSYS' was probably meant (experimental check 'positive-errno-test')}}
// expected-note@-2 {{it is used as a negative error code here}}
      _printk("failed to pin\n");
    return err;
  }
  return 0;
}

void *to_err_ptr(void *obj) {
  int err = wait(obj);

  if (err < 0) {
    _printk("%s waiting\n", err == ERESTARTSYS ? "interrupted" : "error");
// expected-warning@-1 {{'err' is compared with ERESTARTSYS, which is positive, but this function treats 'err' as a kernel error code, and those are negative: '-ERESTARTSYS' was probably meant (experimental check 'positive-errno-test')}}
    return ERR_PTR(err); // expected-note {{it is used as a negative error code here}}
  }
  return obj;
}

void *in_assertion(void *obj) {
  int ret = pin(obj);

  WARN_ON_ONCE(ret == EBUSY);
// expected-warning@-1 {{'ret' is compared with EBUSY, which is positive, but this function treats 'ret' as a kernel error code, and those are negative: '-EBUSY' was probably meant (experimental check 'positive-errno-test')}}
  if (ret)
    return ERR_PTR(ret); // expected-note {{it is used as a negative error code here}}
  return obj;
}

int assigned_negative(void *obj, int id) {
  int ret = -ENOMEM; // expected-note {{it is used as a negative error code here}}
  void *p = lookup(id);

  if (p)
    ret = pin(p);
  if (EAGAIN == ret)
// expected-warning@-1 {{'ret' is compared with EAGAIN, which is positive, but this function treats 'ret' as a kernel error code, and those are negative: '-EAGAIN' was probably meant (experimental check 'positive-errno-test')}}
    return 0;
  return ret;
}

int from_ptr_err(int id) {
  void *p = lookup(id);
  int err;

  if (IS_ERR(p)) {
    err = PTR_ERR(p); // expected-note {{it is used as a negative error code here}}
    if (err != EPROBE_DEFER)
// expected-warning@-1 {{'err' is compared with EPROBE_DEFER, which is positive, but this function treats 'err' as a kernel error code, and those are negative: '-EPROBE_DEFER' was probably meant (experimental check 'positive-errno-test')}}
      _printk("lookup failed\n");
    return err;
  }
  return 0;
}

// ---------------------------------------------------------------------------
// Positive on purpose, or nothing known.

// Ready for both.
int both_signs(void *obj) {
  int ret = pin(obj);

  if (ret == -EPROBE_DEFER || ret == EPROBE_DEFER)
    return 0;
  return ret;
}

// The function keeps positive numbers and turns them round at the end.
int positive_inside(void *obj) {
  int ret = 0;

  if (!obj) {
    ret = ENOMEM;
    goto out;
  }
  ret = -pin(obj);
out:
  if (ret == ENOMEM)
    close_dev(obj);
  return -ret;
}

int turned_round(void *obj) {
  int err = wait(obj);

  if (err == -EINTR)
    return err;
  err = -err;
  if (err == ERESTARTSYS)
    err = EINTR;
  return err;
}

// Nothing says what the function returns.
int unknown_convention(void *obj) {
  int rv = pin(obj);

  if (rv == EAGAIN)
    return 0;
  return rv;
}
