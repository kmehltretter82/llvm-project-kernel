// RUN: %clang_cc1 -fsyntax-only -ffreestanding \
// RUN:   -Wlinux-kernel-missing-error-code -verify=missing %s
// RUN: %clang_cc1 -fsyntax-only -ffreestanding \
// RUN:   -Wlinux-kernel-error-path-success -verify=path %s
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wlinux-kernel \
// RUN:   -Wno-conditional-uninitialized -verify=path %s

typedef _Bool bool;
#define NULL ((void *)0)
#define ENOMEM 12

bool IS_ERR(const void *);
long PTR_ERR(const void *);
void *kzalloc(unsigned long, unsigned int);
void kfree(const void *);
void *get_thing(void);
int get_irq(void);
int setup(void);
int step(void);
void use(void *);
void _dev_err(void *, const char *, ...);

// A failure path without a message that returns a zero error code.

int after_test(void) {
  int ret;
  void *p;

  ret = setup();
  if (ret)
    goto out;
  p = kzalloc(16, 0);
  if (!p) // missing-warning {{'ret' is zero when this failure path leaves, so the function returns success}}
    goto out;
  kfree(p);
out:
  return ret; // missing-note {{'ret' is returned here}}
}

int from_initializer(void) {
  int ret = 0;
  void *p = kzalloc(16, 0);

  if (p == NULL) // missing-warning {{'ret' is zero when this failure path leaves, so the function returns success}}
    goto out;
  ret = step();
  kfree(p);
out:
  return ret; // missing-note {{'ret' is returned here}}
}

int direct_return(void) {
  int ret = 0;
  void *p = kzalloc(16, 0);

  if (!p) // missing-warning {{'ret' is zero when this failure path leaves, so the function returns success}}
    return ret; // missing-note {{'ret' is returned here}}
  ret = step();
  kfree(p);
  return ret;
}

int error_pointer(void) {
  int ret = 0;
  void *t = get_thing();

  if (IS_ERR(t)) // missing-warning {{'ret' is zero when this failure path leaves, so the function returns success}}
    goto out;
  use(t);
  ret = step();
out:
  return ret; // missing-note {{'ret' is returned here}}
}

int negative_result(void) {
  int ret = 0;
  int irq = get_irq();

  if (irq < 0) // missing-warning {{'ret' is zero when this failure path leaves, so the function returns success}}
    goto out;
  use(&irq);
  ret = step();
out:
  return ret; // missing-note {{'ret' is returned here}}
}

// A variable that is never anything but zero is no error code.
int always_zero(void) {
  int ret = 0;
  void *p = kzalloc(16, 0);

  if (!p)
    goto out;
  kfree(p);
out:
  return ret;
}

// The error code is there.

int has_code(void) {
  int ret = setup();
  void *p;

  if (ret)
    goto out;
  p = kzalloc(16, 0);
  if (!p) {
    ret = -ENOMEM;
    goto out;
  }
  kfree(p);
out:
  return ret;
}

int preset(void) {
  int ret = -ENOMEM;
  void *p = kzalloc(16, 0);

  if (!p)
    goto out;
  kfree(p);
  ret = 0;
out:
  return ret;
}

int takes_the_code(void) {
  int ret = 0;
  void *t = get_thing();

  if (IS_ERR(t)) {
    ret = PTR_ERR(t);
    goto out;
  }
  use(t);
out:
  return ret;
}

// "ret = 0;" as a statement says that zero is meant.
int explicit_zero(void) {
  int ret;
  void *p;

  ret = 0;
  p = kzalloc(16, 0);
  if (!p)
    goto out;
  kfree(p);
out:
  return ret;
}

// Not the result of an allocation: NULL may be a normal answer.
int optional(void *arg) {
  int ret = 0;
  void *p = arg;

  if (!p)
    goto out;
  use(p);
  ret = step();
out:
  return ret;
}

// The failure path does not leave.
int goes_on(void) {
  int ret = 0;
  void *p = kzalloc(16, 0);
  int local;

  if (!p)
    p = &local;
  use(p);
  ret = step();
  return ret;
}

// The label does not leave: the function carries on without the buffer.
int carries_on(void) {
  int ret = 0;
  void *p = kzalloc(16, 0);

  if (!p)
    goto no_buffer;
  use(p);
no_buffer:
  ret = step();
  kfree(p);
  return ret;
}

// A test and a jump inside a macro are the macro's business.
#define alloc_or_skip(p, label)                                                \
  do {                                                                         \
    void *__tmp = kzalloc(16, 0);                                              \
    if (!__tmp)                                                                \
      goto label;                                                              \
    p = __tmp;                                                                 \
  } while (0)

int in_macro(void) {
  int ret = 0;
  void *p = NULL;

  alloc_or_skip(p, out);
  ret = step();
out:
  kfree(p);
  return ret;
}

// Refinements of the check with a message.

int still_reported(void *dev) {
  int ret = 0;

  if (!get_thing()) {
    _dev_err(dev, "no thing\n"); // path-note {{failure reported here}}
    goto out;
  }
  ret = step();
out:
  return ret; // path-warning {{'ret' can be zero here, so this return reports success right after a failure was reported}}
}

// The test after the loop tells how the loop ended.
int retry_loop(void *dev) {
  int ret = 0, i;

  for (i = 0; i < 3; i++) {
    ret = step();
    if (!ret)
      break;
  }
  if (i == 3) {
    _dev_err(dev, "step failed\n");
    return ret;
  }
  return 0;
}

int countdown(void *dev) {
  int ret, tries = 5;

  do {
    ret = step();
  } while (ret && --tries);
  if (!tries) {
    _dev_err(dev, "timed out\n");
    return ret;
  }
  return 0;
}

// One operand of the condition tests the variable.
int conjunction(void *dev, int retries) {
  int ret = step();

  if (!retries && ret) {
    _dev_err(dev, "failed: %d\n", ret);
    return ret;
  }
  return 0;
}

int wrapped_conjunction(void *dev) {
  int ret = step();

  if (__builtin_expect(!!(ret && ret != -ENOMEM), 0)) {
    _dev_err(dev, "failed: %d\n", ret);
    goto out;
  }
  ret = 0;
out:
  return ret;
}

// The default of a switch that has a "case 0".
int switch_default(void *dev) {
  int ret = step();

  switch (ret) {
  case 0:
  case -ENOMEM:
    break;
  default:
    _dev_err(dev, "failed: %d\n", ret);
    return ret;
  }
  return 0;
}

// Zero stored after the message is meant.
int deliberate(void *dev) {
  int ret = step();

  if (ret) {
    _dev_err(dev, "failed, going on without it\n");
    ret = 0;
    goto out;
  }
  ret = setup();
out:
  return ret;
}

// A variable that also takes 1 is not an error code.
int tri_state(void *dev) {
  int ret = 0;

  if (!get_thing()) {
    _dev_err(dev, "cannot find it\n");
    goto out;
  }
  ret = 1;
out:
  return ret;
}
