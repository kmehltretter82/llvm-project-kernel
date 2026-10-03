// RUN: %clang_cc1 -fsyntax-only -ffreestanding \
// RUN:   -Wlinux-kernel-unsigned-error-check -verify=unsigned %s
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wlinux-kernel-wrong-check \
// RUN:   -verify=wrong %s
// RUN: %clang_cc1 -fsyntax-only -ffreestanding \
// RUN:   -Wlinux-kernel-error-path-success -verify=path %s
// RUN: %clang_cc1 -fsyntax-only -ffreestanding \
// RUN:   -Wlinux-kernel-errno-truncation -verify=trunc %s
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wlinux-kernel \
// RUN:   -Wno-conditional-uninitialized \
// RUN:   -verify=unsigned,wrong,path,trunc,annot %s
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wlinux-kernel-error-pointer \
// RUN:   -Wlinux-kernel-irq -verify=annot %s
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wno-everything \
// RUN:   -verify=disabled %s

// disabled-no-diagnostics

typedef _Bool bool;
typedef unsigned char u8;
typedef unsigned int u32;

#define EINVAL 22
#define NULL ((void *)0)

bool IS_ERR(const void *);
long PTR_ERR(const void *);
void *kzalloc(unsigned long, unsigned int);
int platform_get_irq(void *, unsigned int);
int count_elems(void *);
unsigned int read_unsigned(void);

int dev_err_probe(void *, int, const char *, ...);
void _dev_err(void *, const char *, ...);
void _dev_info(void *, const char *, ...);
int _printk(const char *, ...);
void drv_dbg(void *, int, const char *, ...);

int step(void);
void *get(void);
int read_reg(u8 *);
void pause(void);

// A negative result stored in an unsigned variable.

struct chan {
  u32 irq;
  int signed_irq;
};

int unsigned_field(struct chan *c, void *pdev) {
  c->irq = platform_get_irq(pdev, 0);
  if (c->irq < 0) // unsigned-warning {{result of platform_get_irq() is stored in a variable of unsigned type 'u32' (aka 'unsigned int'), so this comparison is always false and a negative error code goes undetected}}
    return c->irq;
  return 0;
}

int unsigned_local(void *np) {
  unsigned int n = count_elems(np);
  if (n < 0 || n > 4) // unsigned-warning {{result of count_elems() is stored in a variable of unsigned type 'unsigned int', so this comparison is always false and a negative error code goes undetected}}
    return -EINVAL;
  return 0;
}

int unsigned_always_true(void *pdev) {
  u32 irq;
  irq = platform_get_irq(pdev, 1);
  if (irq >= 0) // unsigned-warning {{result of platform_get_irq() is stored in a variable of unsigned type 'u32' (aka 'unsigned int'), so this comparison is always true and a negative error code goes undetected}}
    return 1;
  return 0;
}

int unsigned_inline(void *pdev) {
  u32 irq;
  if ((irq = platform_get_irq(pdev, 0)) < 0) // unsigned-warning {{result of platform_get_irq() is stored in a variable of unsigned type 'u32' (aka 'unsigned int'), so this comparison is always false and a negative error code goes undetected}}
    return -EINVAL;
  return irq;
}

int signed_storage(struct chan *c, void *pdev) {
  c->signed_irq = platform_get_irq(pdev, 0);
  if (c->signed_irq < 0)
    return c->signed_irq;
  return 0;
}

int unsigned_callee(void) {
  u32 v = read_unsigned();
  if (v < 0)
    return -EINVAL;
  return 0;
}

int explicit_conversion(void *pdev) {
  u32 v = (u32)platform_get_irq(pdev, 0);
  if (v < 0)
    return -EINVAL;
  return 0;
}

int upper_bound_only(void *np) {
  unsigned int n = count_elems(np);
  if (n > 4)
    return -EINVAL;
  return 0;
}

// A failure test on something other than the value just stored.

struct bridge;
struct glue {
  struct bridge *bridge;
  struct bridge *other;
};
struct bridge *bridge_probe(void *);

int wrong_container(struct glue *g, void *pdev) {
  g->bridge = bridge_probe(pdev);
  if (IS_ERR(g)) // wrong-warning {{this tests 'g', but the previous statement stored the result of bridge_probe() in 'g->bridge' and has already dereferenced 'g'}}
    return PTR_ERR(g);
  return 0;
}

int wrong_container_null(struct glue *g) {
  g->bridge = kzalloc(8, 0);
  if (!g) // wrong-warning {{this tests 'g', but the previous statement stored the result of kzalloc() in 'g->bridge' and has already dereferenced 'g'}}
    return -EINVAL;
  return 0;
}

int wrong_sibling(struct glue *g, void *pdev) {
  g->bridge = bridge_probe(pdev);
  if (IS_ERR(g->other)) // wrong-warning {{this tests 'g->other', but the previous statement stored the result of bridge_probe() in 'g->bridge'}}
    return -EINVAL;
  return 0;
}

int wrong_local(void) {
  void *a = kzalloc(8, 0);
  void *b;
  if (!a)
    return -EINVAL;
  b = kzalloc(8, 0);
  if (!a) // wrong-warning {{this tests 'a', but the previous statement stored the result of kzalloc() in 'b'}}
    return -EINVAL;
  return b != NULL;
}

int right_value(struct glue *g, void *pdev) {
  g->bridge = bridge_probe(pdev);
  if (IS_ERR(g->bridge))
    return PTR_ERR(g->bridge);
  return 0;
}

int both_tested(void) {
  void *a = kzalloc(8, 0);
  void *b = kzalloc(8, 0);
  if (!a || !b)
    return -EINVAL;
  return 0;
}

int unrelated_null_test(struct glue *g, void *pdev, struct bridge *fallback) {
  g->bridge = bridge_probe(pdev);
  if (!fallback)
    return -EINVAL;
  return 0;
}

// A return that reports success right after a failure message.

int path_direct(void *dev) {
  int ret;
  void *res;

  ret = step();
  if (ret)
    return ret;
  res = get();
  if (!res) {
    _dev_err(dev, "no resource\n"); // path-note {{failure reported here}}
    return ret; // path-warning {{'ret' can be zero here, so this return reports success right after a failure was reported}}
  }
  return 0;
}

int path_poll_loop(void *adapter) {
  int ret;
  int tries;
  u8 status;

  for (tries = 0; tries < 100; tries++) {
    ret = read_reg(&status);
    if (ret)
      break;
    else if (status & 1)
      return 0;
    pause();
  }
  drv_dbg(adapter, 1, "poll card status failed, tries = %d\n", tries); // path-note {{failure reported here}}
  return ret; // path-warning {{'ret' can be zero here, so this return reports success right after a failure was reported}}
}

int path_goto(void) {
  int ret = step();
  void *res;

  if (ret)
    goto out;
  res = get();
  if (!res) {
    _printk("\001" "3" "allocation failed\n"); // path-note {{failure reported here}}
    goto out;
  }
  ret = step();
out:
  return ret; // path-warning {{'ret' can be zero here, so this return reports success right after a failure was reported}}
}

int path_probe(void *dev) {
  int ret = step();

  if (ret)
    return ret;
  if (!get())
    return dev_err_probe(dev, ret, "nothing there\n"); // path-warning {{'ret' can be zero here, so dev_err_probe() returns success}}
  return 0;
}

int message_for_the_error(void *dev) {
  int ret = step();

  if (ret) {
    _dev_err(dev, "step failed\n");
    return ret;
  }
  return 0;
}

int message_then_carry_on(void *dev) {
  int ret = step();

  if (ret)
    return ret;
  if (!get())
    _dev_err(dev, "failed to get the optional thing\n");
  return ret;
}

int informational_message(void *dev) {
  int ret = step();

  if (ret)
    return ret;
  if (!get()) {
    _dev_info(dev, "lookup failed, using the default\n");
    return ret;
  }
  return 0;
}

int informational_printk(void) {
  int ret = step();

  if (ret)
    return ret;
  if (!get()) {
    _printk("\001" "6" "lookup failed, using the default\n");
    return ret;
  }
  return 0;
}

int error_code_set(void *dev) {
  int ret = step();

  if (ret)
    return ret;
  if (!get()) {
    _dev_err(dev, "no resource\n");
    ret = -EINVAL;
    return ret;
  }
  return 0;
}

// A negative errno returned through a type that cannot carry it.

u8 narrow_return(int x) {
  if (x)
    return -EINVAL; // trunc-warning {{negative errno returned from a function returning 'u8' (aka 'unsigned char') is truncated and cannot be recognized by the caller}}
  return 1;
}

unsigned int wide_return(int x) {
  if (x)
    return -EINVAL;
  return 1;
}

// A contract stated by an annotation instead of the built-in table.

#define __returns_err_ptr \
  __attribute__((annotate("linux_kernel::returns_err_ptr")))
#define __returns_null_on_failure \
  __attribute__((annotate("linux_kernel::returns_null_on_failure")))

__returns_err_ptr void *widget_get(void *);
__returns_null_on_failure void *widget_alloc(void);
void *widget_other(void);

int annotated_err_ptr(void *dev) {
  void *w = widget_get(dev);
  if (!w) // annot-warning {{widget_get returns an encoded error pointer on failure, which a NULL test does not detect; use IS_ERR()}}
    return -EINVAL;
  return 0;
}

int annotated_null(void) {
  void *w = widget_alloc();
  if (IS_ERR(w)) // annot-warning {{widget_alloc returns NULL on failure, which IS_ERR does not detect; test the pointer for NULL}}
    return -EINVAL;
  return 0;
}

int not_annotated(void) {
  void *w = widget_other();
  if (!w)
    return -EINVAL;
  return 0;
}

// A boolean test of an IRQ number after a negative test only handles zero.

int irq_negative_then_zero(void *pdev) {
  int irq = platform_get_irq(pdev, 0);
  if (irq < 0)
    return irq;
  if (!irq)
    return -EINVAL;
  return irq;
}

int irq_boolean_only(void *pdev) {
  int irq = platform_get_irq(pdev, 0);
  if (!irq) // annot-warning {{platform_get_irq() returns an IRQ number or a negative errno; a boolean test does not detect errors; test for a negative value}}
    return -EINVAL;
  return irq;
}
