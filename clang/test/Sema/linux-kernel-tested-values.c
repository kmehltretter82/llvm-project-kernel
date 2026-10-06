// RUN: %clang_cc1 -fsyntax-only -ffreestanding \
// RUN:   -Wlinux-kernel-deref-after-check -verify=deref %s
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wlinux-kernel-ptr-err-valid \
// RUN:   -verify=valid %s
// RUN: %clang_cc1 -fsyntax-only -ffreestanding \
// RUN:   -Wlinux-kernel-error-pointer-zero -verify=zero %s
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wall -verify=wall %s

// wall-no-diagnostics

typedef _Bool bool;
#define NULL ((void *)0)
#define EINVAL 22
#define unlikely(x) __builtin_expect(!!(x), 0)

bool IS_ERR(const void *);
bool IS_ERR_OR_NULL(const void *);
long PTR_ERR(const void *);
void *ERR_PTR(long);
int _printk(const char *fmt, ...);

struct thing {
  int id;
  int count;
  struct thing *next;
};

struct dev {
  struct thing *priv;
  struct dev *parent;
  int flags;
};

void init_priv(struct dev *d);
void unrelated(void);

// A pointer that a test found to be NULL is dereferenced.

int basic(struct thing *t) {
  if (!t) // deref-note {{'t' is tested here and the path goes on with it being NULL}}
    _printk("no thing\n");
  return t->id; // deref-warning {{'t' is dereferenced here on a path where the earlier test found it to be NULL}}
}

int compared(struct thing *t) {
  if (t == NULL) // deref-note {{'t' is tested here}}
    unrelated();
  t->count++; // deref-warning {{'t' is dereferenced here}}
  return 0;
}

int unlikely_test(struct thing *t) {
  if (unlikely(!t)) // deref-note {{'t' is tested here}}
    _printk("no thing\n");
  return t->id; // deref-warning {{'t' is dereferenced here}}
}

int either(struct thing *t) {
  if (IS_ERR_OR_NULL(t)) // deref-note {{'t' is tested here}}
    _printk("bad thing\n");
  return t->id; // deref-warning {{'t' is dereferenced here}}
}

int leaves(struct thing *t) {
  if (!t)
    return -EINVAL;
  return t->id;
}

int reassigned(struct thing *t, struct thing *fallback) {
  if (!t)
    t = fallback;
  return t->id;
}

int ternary(struct thing *t) { return t ? t->id : 0; }

int and_guard(struct thing *t) {
  if (t && t->id)
    return 1;
  return 0;
}

int or_guard(struct thing *t) {
  if (!t || !t->id)
    return 0;
  return t->count;
}

// The search ends where a later branch contradicts the path.

int second_test(struct thing *t) {
  int n = 0;

  if (!t)
    n = 1;
  if (t)
    n += t->id;
  return n;
}

int correlated_error(struct thing *t) {
  int ret = 0;

  if (!t)
    ret = -EINVAL;
  if (ret)
    return ret;
  return t->id;
}

int correlated_flag(struct thing *t, int n) {
  int have = 1;

  if (t == NULL)
    have = 0;
  n++;
  if (have)
    return t->id + n;
  return n;
}

int correlated_switch(struct thing *t, int mode) {
  int ok = 0;

  if (!t)
    mode = 0;
  switch (mode) {
  case 0:
    return 0;
  case 1:
    ok = 1;
    break;
  default:
    break;
  }
  return t->id + ok;
}

int repeated_condition(struct thing *t, int verbose) {
  if (verbose && !t)
    return -EINVAL;
  if (!verbose)
    return 0;
  return t->id;
}

// A loop that walks a list ends with NULL when nothing was found.

int loop_exit(struct thing *t, int id) {
  while (t && t->id != id) // deref-note {{'t' is tested here}}
    t = t->next;
  return t->count; // deref-warning {{'t' is dereferenced here}}
}

int loop_exit_tested(struct thing *t, int id) {
  while (t && t->id != id)
    t = t->next;
  if (!t)
    return -EINVAL;
  return t->count;
}

// The condition of a do-while loop: when the first operand of "&&" is
// false the loop ends, whatever the second one is.

int do_while_exit(struct thing *t, struct thing *end) {
  int n = 0;

  do {
    n += t->id;
    t = t->next;
  } while (t && t != end);
  if (!t)
    return -EINVAL;
  return n + t->count;
}

int do_while_exit_untested(struct thing *t, struct thing *end) {
  int n = 0;

  do {
    n += t->id;
    t = t->next;
  } while (t && t != end); // deref-note {{'t' is tested here}}
  return n + t->count; // deref-warning {{'t' is dereferenced here}}
}

// Members.

int member(struct dev *d) {
  if (!d->priv) // deref-note {{'d->priv' is tested here}}
    _printk("no private data\n");
  return d->priv->id; // deref-warning {{'d->priv' is dereferenced here}}
}

int member_set_by_call(struct dev *d) {
  if (!d->priv)
    init_priv(d);
  return d->priv->id;
}

int member_set_through_alias(struct dev *d, struct dev *other,
                             struct thing *t) {
  if (!d->priv)
    other->priv = t;
  return d->priv->id;
}

int member_after_other_call(struct dev *d) {
  if (!d->priv) // deref-note {{'d->priv' is tested here}}
    unrelated();
  return d->priv->id; // deref-warning {{'d->priv' is dereferenced here}}
}

int root_reassigned(struct dev *d) {
  if (!d->priv)
    d = d->parent;
  return d->priv->id;
}

// A function whose body is here: it is known which members it stores to.

static void count_miss(struct dev *d) { d->flags++; }

static void set_priv(struct dev *d, struct thing *t) { d->priv = t; }

void fill_slot(struct thing **slot);

int member_after_static_call(struct dev *d) {
  if (!d->priv) // deref-note {{'d->priv' is tested here}}
    count_miss(d);
  return d->priv->id; // deref-warning {{'d->priv' is dereferenced here}}
}

int member_set_by_static_call(struct dev *d, struct thing *t) {
  if (!d->priv)
    set_priv(d, t);
  return d->priv->id;
}

int member_address_passed(struct dev *d) {
  if (!d->priv)
    fill_slot(&d->priv);
  return d->priv->id;
}

// What the code before the test establishes counts as well.

int counted_before(struct thing *t) {
  int n = 0, i, sum = 0;

  if (t)
    n = t->count;
  for (i = 0; i < n; i++)
    sum += t->id;
  return sum;
}

int flag_before(struct dev *d, int status) {
  int done = 0;

  if (status & 1) {
    if (d->priv) {
      d->priv->count = 0;
      done = 1;
    }
  }
  if (status & 2) {
    _printk("second\n");
    if (d->priv)
      d->priv->count++;
  }
  if (done)
    return d->priv->id;
  return 0;
}

// A copy of a member holds what the member holds.

int copy_of_member(struct dev *d) {
  struct thing *t = d->priv;

  if (!t)
    _printk("no private data\n");
  if (d->priv)
    return t->id;
  return 0;
}

int copy_tested_through_member(struct dev *d) {
  struct thing *t = d->priv;

  if (!d->priv) // deref-note {{'d->priv' is tested here}}
    _printk("no private data\n");
  return t->id + d->priv->count; // deref-warning {{'d->priv' is dereferenced here}}
}

// Taking the address of a member is not an access.

int member_address(struct thing *t) {
  int *p;

  if (!t)
    _printk("no thing\n");
  p = &t->id;
  return p != NULL;
}

// A test in a macro is not the author's statement about the pointer.

#define CHECK(p)                                                               \
  do {                                                                         \
    if (!(p))                                                                  \
      _printk("null\n");                                                       \
  } while (0)

int macro_test(struct thing *t) {
  CHECK(t);
  return t->id;
}

// The pointer is handed to a function that dereferences it first thing.

static int reads(struct thing *t) {
  return t->id; // #reads
}

static int reads_through(struct thing *t) {
  return reads(t) + 1; // #through
}

static int careful(struct thing *t) {
  if (!t)
    return 0;
  return t->id;
}

static int reads_later(struct thing *t, int n) {
  if (n)
    return 0;
  return t->id;
}

int through_call(struct thing *t) {
  if (!t) // deref-note {{'t' is tested here}}
    _printk("no thing\n");
  return reads(t); // deref-warning {{'t' is passed to 'reads', which dereferences it, on a path where the earlier test found it to be NULL}} \
                   // deref-note@#reads {{is dereferenced here}}
}

int through_two_calls(struct thing *t) {
  if (!t) // deref-note {{'t' is tested here}}
    _printk("no thing\n");
  return reads_through(t); // deref-warning {{'t' is passed to 'reads_through', which dereferences it}} \
                           // deref-note@#through {{is dereferenced here}}
}

int through_careful_call(struct thing *t, int n) {
  if (!t)
    _printk("no thing\n");
  return careful(t) + reads_later(t, n);
}

// PTR_ERR() of a pointer that IS_ERR() has cleared.

long rollback(struct thing *t, int count) {
  if (IS_ERR(t)) // valid-note {{tested here}}
    goto out;
  if (count <= 0)
    goto out;
  return t->id;
out:
  return PTR_ERR(t); // valid-warning {{'t' is passed to PTR_ERR(), but the IS_ERR() test has shown that it is not an error pointer on this path}}
}

long error_branch(struct thing *t) {
  if (IS_ERR(t))
    return PTR_ERR(t);
  return t->id;
}

long retested(struct thing *t, int count) {
  if (!IS_ERR(t) && count > 0)
    return t->id;
  if (IS_ERR(t))
    return PTR_ERR(t);
  return -EINVAL;
}

// Cleared behind the test: PTR_ERR() is meant to give 0.
long cleared(struct thing *t) {
  int n = 0;

  if (!IS_ERR(t)) {
    n = t->id;
    t = NULL;
  }
  if (n)
    _printk("%d\n", n);
  return PTR_ERR(t);
}

// ERR_PTR() of an error code that is zero.

int prepare(int n);
void finish(void);
struct thing *alloc_thing(void);

struct thing *make(int n) {
  struct thing *t;
  int err = prepare(n);

  if (err) // zero-note {{'err' is found to be zero here}}
    goto out;
  t = alloc_thing();
  if (t)
    return t;
out:
  finish();
  return ERR_PTR(err); // zero-warning {{'err' is zero on every path to this call, so ERR_PTR() returns NULL instead of an error pointer}}
}

struct thing *make_ok(int n) {
  struct thing *t;
  int err = prepare(n);

  if (err)
    goto out;
  t = alloc_thing();
  if (t)
    return t;
  err = -EINVAL;
out:
  finish();
  return ERR_PTR(err);
}

// Zero is dealt with right at the test: NULL is what is meant.
struct thing *revalidate(struct thing *t, int n) {
  if (t) {
    int err = prepare(n);

    if (err <= 0) {
      if (!err)
        finish();
      return ERR_PTR(err);
    }
  }
  return t;
}

// NULL for success is what this function returns: it never hands out an
// object.
struct thing *mkdir_like(int n) {
  int err = prepare(n);

  if (err)
    goto out;
  finish();
out:
  return ERR_PTR(err);
}

// "dev ?: ERR_PTR(err)" asks for the error only if there is no device.

struct thing *make_or_error(int n) {
  struct thing *t = NULL;
  int err = prepare(n);

  if (err)
    goto out;
  t = alloc_thing();
  if (!t)
    err = -EINVAL;
out:
  finish();
  return t ?: ERR_PTR(err);
}
