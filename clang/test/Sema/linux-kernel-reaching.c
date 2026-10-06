// What a variable holds, inside a branch or a loop and behind a goto.  The
// checks that walk the syntax tree follow assignments only at the top level
// of a function and up to its first goto.  Elsewhere they ask the CFG: a use
// sees an assignment if that is the only definition that reaches it.
//
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wlinux-kernel \
// RUN:   -Wlinux-kernel-unchecked-allocation \
// RUN:   -Wlinux-kernel-error-pointer-deref -verify=expected,cfg %s
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wlinux-kernel \
// RUN:   -Wlinux-kernel-unchecked-allocation \
// RUN:   -Wlinux-kernel-error-pointer-deref \
// RUN:   -flinux-kernel-experimental=walk-origins -verify %s
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wall -verify=wall %s

// wall-no-diagnostics

typedef _Bool bool;
#define NULL ((void *)0)
#define ENOMEM 12
#define ENODEV 19

bool IS_ERR(const void *p);
long PTR_ERR(const void *p);
void *kmalloc(unsigned long size, unsigned int flags);
void *kzalloc(unsigned long size, unsigned int flags);
void *vmalloc(unsigned long size);
void kfree(const void *p);
unsigned long copy_from_user(void *to, const void *from, unsigned long n);
int platform_get_irq(void *pdev, unsigned int n);
int step(int n);
void note(int n);

struct dev {
  int a, n, mode;
  int *p;
  struct dev *other;
};

struct dev *dev_lookup(int n) __attribute__((annotate("linux_kernel::returns_err_ptr")));
struct dev *dev_find(int n);
void fill(struct dev **slot);

// ---------------------------------------------------------------------------
// The walk and the CFG agree at the top level.

int top_level(void) {
  struct dev *o;

  o = dev_lookup(1);
  if (!o) // expected-warning {{dev_lookup returns an encoded error pointer on failure, which a NULL test does not detect; use IS_ERR()}}
    return -ENODEV;
  return o->a;
}

// ---------------------------------------------------------------------------
// Where the walk gives up.

int in_branch(struct dev *d) {
  struct dev *o;

  if (d->mode) {
    o = dev_lookup(1);
    if (!o) // cfg-warning {{dev_lookup returns an encoded error pointer on failure, which a NULL test does not detect; use IS_ERR()}}
      return -ENODEV;
    note(o->a);
  }
  return 0;
}

int in_loop(struct dev *d) {
  struct dev *o;
  int i;

  for (i = 0; i < d->n; i++) {
    o = dev_lookup(i);
    if (!o) // cfg-warning {{dev_lookup returns an encoded error pointer on failure, which a NULL test does not detect; use IS_ERR()}}
      return -ENODEV;
    note(o->a);
  }
  return 0;
}

int in_switch(struct dev *d) {
  int *q;

  switch (d->mode) {
  case 1:
    q = kmalloc(sizeof(*q), 0);
    if (IS_ERR(q)) // cfg-warning {{kmalloc returns NULL on failure, which IS_ERR does not detect; test the pointer for NULL}}
      return PTR_ERR(q); // cfg-warning {{kmalloc returns NULL on failure, which PTR_ERR converts to success; test the pointer for NULL and return an errno}}
    *q = 0;
    kfree(q);
    break;
  default:
    break;
  }
  return 0;
}

int behind_goto(struct dev *d) {
  struct dev *o;
  int ret = 0;

  if (step(1))
    goto out;
  o = dev_lookup(1);
  if (!o) { // cfg-warning {{dev_lookup returns an encoded error pointer on failure, which a NULL test does not detect; use IS_ERR()}}
    ret = -ENODEV;
    goto out;
  }
  note(o->a);
out:
  note(d->a);
  return ret;
}

int behind_label(struct dev *d) {
  struct dev *o;

  if (step(1))
    goto skip;
  note(d->a);
skip:
  o = dev_lookup(1);
  if (!o) // cfg-warning {{dev_lookup returns an encoded error pointer on failure, which a NULL test does not detect; use IS_ERR()}}
    return -ENODEV;
  return o->a;
}

int unchecked_in_loop(struct dev *d) {
  struct dev *o;
  int i;

  for (i = 0; i < d->n; i++) {
    o = kzalloc(sizeof(*o), 0);
    o->a = i; // cfg-warning {{'o' holds the result of 'kzalloc', which is NULL when the allocation fails, and is dereferenced here without a test}}
    kfree(o);
  }
  return 0;
}

int deref_in_loop(struct dev *d) {
  struct dev *o;
  int i, sum = 0;

  for (i = 0; i < d->n; i++) {
    o = dev_lookup(i);
    sum += o->a; // cfg-warning {{'o' holds an encoded error pointer if 'dev_lookup' failed, and is dereferenced here without an IS_ERR() test}}
  }
  return sum;
}

int mismatch_in_branch(struct dev *d) {
  int *q;

  if (d->mode) {
    q = vmalloc(64);
    if (!q)
      return -ENOMEM;
    *q = 0;
    kfree(q); // cfg-warning {{vmalloc() result must not be released with kfree(); use vfree()}}
  }
  return 0;
}

int irq_in_loop(struct dev *d) {
  int irq, i;

  for (i = 0; i < d->n; i++) {
    irq = platform_get_irq(d, i);
    if (!irq) // cfg-warning {{platform_get_irq() returns an IRQ number or a negative errno; a boolean test does not detect errors; test for a negative value}}
      return -ENODEV;
    note(irq);
  }
  return 0;
}

long usercopy_behind_goto(struct dev *d, const void *from) {
  char buf[8];
  long left;

  if (step(1))
    goto out;
  left = copy_from_user(buf, from, sizeof(buf));
  if (left < 0) // cfg-warning {{copy_from_user returns the number of bytes not copied, never a negative errno; test for nonzero and convert failures to -EFAULT}}
    return left;
  note(buf[0]);
out:
  return 0;
}

// A member that is reached through a variable.
int member_in_branch(struct dev *d) {
  if (d->mode) {
    d->other = dev_lookup(1);
    if (!d->other) // cfg-warning {{dev_lookup returns an encoded error pointer on failure, which a NULL test does not detect; use IS_ERR()}}
      return -ENODEV;
    note(d->other->a);
  }
  return 0;
}

int member_behind_goto(struct dev *d) {
  if (step(1))
    goto out;
  d->p = kmalloc(sizeof(int), 0);
  if (IS_ERR(d->p)) // cfg-warning {{kmalloc returns NULL on failure, which IS_ERR does not detect; test the pointer for NULL}}
    return PTR_ERR(d->p); // cfg-warning {{kmalloc returns NULL on failure, which PTR_ERR converts to success; test the pointer for NULL and return an errno}}
out:
  return 0;
}

// ---------------------------------------------------------------------------
// Where two definitions meet, nothing is known.

int two_ways(struct dev *d) {
  struct dev *o;

  if (d->mode)
    o = dev_lookup(1);
  else
    o = dev_find(1);
  if (!o)
    return -ENODEV;
  return o->a;
}

int one_way(struct dev *d) {
  struct dev *o = d->other;

  if (d->mode)
    o = dev_lookup(1);
  if (!o)
    return -ENODEV;
  return o->a;
}

// The test sees the assignment of the turn before, and on the first turn
// the initializer.
int carried(struct dev *d) {
  struct dev *o = NULL;
  int i;

  for (i = 0; i < d->n; i++) {
    if (!o)
      note(i);
    o = dev_lookup(i);
  }
  return 0;
}

int again(struct dev *d) {
  struct dev *o = dev_find(0);

retry:
  if (!o)
    return -ENODEV;
  if (o->a) {
    o = dev_lookup(o->a);
    goto retry;
  }
  return 0;
}

// The member had a value before the function ran.
int member_one_way(struct dev *d) {
  if (d->mode)
    d->other = dev_lookup(1);
  if (!d->other)
    return -ENODEV;
  return 0;
}

// Another object behind the same name.
int member_of_another(struct dev *d) {
  if (d->mode) {
    d->other = dev_lookup(1);
    d = d->other;
    if (!d->other)
      return -ENODEV;
  }
  return 0;
}

// The allocation is tested where it is assigned.
int tested_in_condition(struct dev **slot) {
  struct dev *o;

  if (!(o = *slot = kzalloc(sizeof(*o), 0)))
    return -ENOMEM;
  o->a = 1;
  return 0;
}

// The member is tested, and its value is copied afterwards.
int member_tested_then_copied(struct dev *d) {
  struct dev *o;

  if (step(1))
    goto out;
  d->other = dev_lookup(1);
  if (IS_ERR(d->other))
    return PTR_ERR(d->other);
  o = d->other;
  note(o->a);
out:
  return 0;
}

// ---------------------------------------------------------------------------
// What ends an assignment's say.

int address_taken(struct dev *d) {
  struct dev *o;

  if (d->mode) {
    o = dev_lookup(1);
    fill(&o);
    if (!o)
      return -ENODEV;
  }
  return 0;
}

int released(struct dev *d) {
  int *q;

  if (d->mode) {
    q = kmalloc(sizeof(*q), 0);
    kfree(q);
    if (IS_ERR(q))
      return -ENOMEM;
  }
  return 0;
}

int stepped(struct dev *d) {
  int irq;

  if (d->mode) {
    irq = platform_get_irq(d, 0);
    irq++;
    if (!irq)
      return -ENODEV;
  }
  return 0;
}
