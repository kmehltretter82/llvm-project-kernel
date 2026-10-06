// RUN: %clang_cc1 -fsyntax-only -ffreestanding \
// RUN:   -Wlinux-kernel-error-pointer-deref -verify=deref %s
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wlinux-kernel-ptr-err-zero \
// RUN:   -Wlinux-kernel-wrong-check -verify=ptrerr %s
// RUN: %clang_cc1 -fsyntax-only -ffreestanding \
// RUN:   -Wlinux-kernel-deref-before-check -verify=order %s
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wall -verify=wall %s

// wall-no-diagnostics

typedef _Bool bool;
#define NULL ((void *)0)
#define ENOMEM 12
#define ENODEV 19
#define EINVAL 22
#define unlikely(x) __builtin_expect(!!(x), 0)

bool IS_ERR(const void *);
bool IS_ERR_OR_NULL(const void *);
long PTR_ERR(const void *);
void *ERR_PTR(long);
void use(void *);
void warn(void);

struct thing {
  int id;
  int count;
  struct thing *next;
};

struct holder {
  struct thing *a;
  struct thing *b;
  struct thing own;
};

// An error pointer function, by its body.
static struct thing *get_thing(struct holder *h) { // #get_thing
  if (!h)
    return ERR_PTR(-ENODEV);
  return &h->own;
}

struct thing *lookup_thing(int id);

// The result of an error pointer function, dereferenced untested.

int untested(struct holder *h) {
  struct thing *t = get_thing(h);

  return t->id; // deref-warning {{'t' holds an encoded error pointer if 'get_thing' failed, and is dereferenced here without an IS_ERR() test}} \
                // deref-note@#get_thing {{the return convention of 'get_thing' was inferred from its definition}}
}

int tested(struct holder *h) {
  struct thing *t = get_thing(h);

  if (IS_ERR(t))
    return PTR_ERR(t);
  return t->id;
}

// Tested elsewhere in the function: not this check's business.
int tested_later(struct holder *h) {
  struct thing *t = get_thing(h);
  int id = 0;

  if (h->b)
    id = h->b->id;
  if (!IS_ERR(t))
    id += t->id;
  return id;
}

int not_an_error_pointer(int id) {
  struct thing *t = lookup_thing(id);

  return t->id;
}

// PTR_ERR() of NULL is 0.

int ptr_err_of_null(int id) {
  struct thing *t = lookup_thing(id);

  if (!t)
    return PTR_ERR(t); // ptrerr-warning {{t is NULL on this path, and PTR_ERR() of NULL is 0; the failure becomes success}}
  return t->id;
}

int ptr_err_or_null(int id) {
  struct thing *t = lookup_thing(id);

  if (IS_ERR_OR_NULL(t))
    return PTR_ERR(t); // ptrerr-warning {{t is NULL or an error pointer here, and PTR_ERR() of NULL is 0; the failure becomes success}}
  return t->id;
}

int ptr_err_or_null_handled(int id) {
  struct thing *t = lookup_thing(id);

  if (IS_ERR_OR_NULL(t))
    return t ? PTR_ERR(t) : -ENOMEM;
  return t->id;
}

// PTR_ERR() of another pointer than the one that was tested.

int other_pointer(struct holder *h) {
  h->a = lookup_thing(1);
  h->b = lookup_thing(2);
  if (IS_ERR(h->b))
    return PTR_ERR(h->a); // ptrerr-warning {{error code is taken from h->a, but the error test is on h->b}}
  return 0;
}

int same_pointer(struct holder *h) {
  h->a = lookup_thing(1);
  if (IS_ERR(h->a))
    return PTR_ERR(h->a);
  return 0;
}

int either_pointer(struct holder *h) {
  if (IS_ERR(h->a) || IS_ERR(h->b))
    return IS_ERR(h->a) ? PTR_ERR(h->a) : PTR_ERR(h->b);
  return 0;
}

int nested_test(struct holder *h, struct thing *spare) {
  if (IS_ERR(h->a)) {
    if (IS_ERR(spare))
      return PTR_ERR(spare);
    h->a = spare;
  }
  return 0;
}

// A NULL test after every path has dereferenced the pointer.

int checked_too_late(struct thing *t) {
  int id = t->id; // order-note {{'t' is dereferenced here}}

  if (!t) // order-warning {{'t' is tested for NULL here, but every path to this test has dereferenced it}}
    return -EINVAL;
  return id;
}

int checked_too_late_wrapped(struct thing *t) {
  t->count++; // order-note {{'t' is dereferenced here}}
  if (unlikely(t == NULL)) // order-warning {{'t' is tested for NULL here, but every path to this test has dereferenced it}}
    return -EINVAL;
  return 0;
}

int checked_first(struct thing *t) {
  if (!t)
    return -EINVAL;
  return t->id;
}

// Only one path has dereferenced it.
int one_path(struct thing *t, int flag) {
  int id = 0;

  if (flag)
    id = t->id;
  if (!t)
    return -EINVAL;
  return id;
}

// A new value since the dereference.
int reassigned(struct thing *t) {
  int id = t->id;

  t = t->next;
  if (!t)
    return id;
  return t->id;
}

int list_walk(struct thing *t) {
  int n = 0;

  while (t) {
    n += t->count;
    t = t->next;
  }
  return n;
}

// The address of a member is not an access.
int member_address(struct thing *t) {
  int *p = &t->count;

  if (!t)
    return -EINVAL;
  return *p;
}

// A test that a macro makes says nothing.
#define check_and_warn(p)                                                      \
  do {                                                                         \
    if (!(p))                                                                  \
      warn();                                                                  \
  } while (0)

int macro_test(struct thing *t) {
  int id = t->id;

  check_and_warn(t);
  return id;
}

// Handed untested to a function that dereferences it.

static int thing_id(struct thing *t) {
  return t->id; // deref-note {{'t' is dereferenced here}}
}

static int thing_id_checked(struct thing *t) {
  if (IS_ERR(t))
    return -EINVAL;
  return t->id;
}

int untested_argument(struct holder *h) {
  struct thing *t = get_thing(h);

  return thing_id(t); // deref-warning {{'t' holds an encoded error pointer if 'get_thing' failed, and is dereferenced here without an IS_ERR() test}} \
                      // deref-note@#get_thing {{the return convention of 'get_thing' was inferred from its definition}}
}

int argument_tested_by_callee(struct holder *h) {
  struct thing *t = get_thing(h);

  return thing_id_checked(t);
}

int argument_only_passed_on(struct holder *h) {
  struct thing *t = get_thing(h);

  use(t);
  return 0;
}
