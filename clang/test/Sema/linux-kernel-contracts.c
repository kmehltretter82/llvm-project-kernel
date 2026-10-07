// Contracts that are inferred from function bodies.
//
// With the bodies of this translation unit only:
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wlinux-kernel-error-pointer \
// RUN:   -verify %s
//
// With the facts of another translation unit, closed into a contracts file:
// RUN: rm -rf %t && mkdir %t
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -DOTHER_UNIT \
// RUN:   -flinux-kernel-emit-facts=%t/facts %s
// RUN: FileCheck --check-prefix=FACTS --input-file=%t/facts %s
// RUN: %python %S/../../utils/linux-kernel/infer-contracts.py \
// RUN:   -o %t/contracts %t/facts
// RUN: FileCheck --check-prefix=CONTRACTS --input-file=%t/contracts %s
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wlinux-kernel-error-pointer \
// RUN:   -flinux-kernel-contracts=%t/contracts -verify=expected,file %s
//
// RUN: not %clang_cc1 -fsyntax-only -ffreestanding \
// RUN:   -Wlinux-kernel-error-pointer \
// RUN:   -flinux-kernel-contracts=%t/missing %s 2>&1 \
// RUN:   | FileCheck --check-prefix=MISSING %s
// MISSING: error: cannot open Linux kernel contracts or facts file

typedef _Bool bool;
#define NULL ((void *)0)
#define ENOMEM 12
#define ENODEV 19

bool IS_ERR(const void *);
long PTR_ERR(const void *);
void *ERR_PTR(long);
void *kzalloc(unsigned long, unsigned int);

struct item {
  int id;
  struct item *next;
};

struct ctx {
  struct item *first;
  struct item slot;
};

#ifdef OTHER_UNIT

// FACTS-DAG: fn{{	}}ext_err{{	.*	}}EV{{	}}-
struct item *ext_err(struct ctx *c) {
  if (!c)
    return ERR_PTR(-ENODEV);
  return &c->slot;
}

// FACTS-DAG: fn{{	}}ext_null{{	.*	}}NV{{	}}-
struct item *ext_null(struct ctx *c) {
  if (!c)
    return NULL;
  return &c->slot;
}

// The body of ext_err() is here, so nothing is left to resolve.
// FACTS-DAG: fn{{	}}ext_wrap{{	.*	}}eV{{	}}-
struct item *ext_wrap(struct ctx *c) { return ext_err(c); }

// FACTS-DAG: fn{{	}}ext_mixed{{	.*	}}ENV{{	}}-
struct item *ext_mixed(struct ctx *c) {
  if (!c)
    return NULL;
  if (c->first)
    return ERR_PTR(-ENODEV);
  return &c->slot;
}

// The result of a function that is defined nowhere, tested for NULL: once
// the test has passed, the author takes it for an object.
struct item *ext_far(struct ctx *c);
// FACTS-DAG: fn{{	}}ext_chain{{	.*	}}E,k:ext_far{{	}}ext_far
// CONTRACTS-DAG: err_ptr{{	}}ext_chain
struct item *ext_chain(struct ctx *c) {
  struct item *i = ext_far(c);

  if (!i)
    return ERR_PTR(-ENOMEM);
  return i;
}

// The same with an IS_ERR() test.
// FACTS-DAG: fn{{	}}ext_tested{{	.*	}}e,t:ext_far{{	}}IS_ERR,ext_far
// CONTRACTS-DAG: err_ptr{{	}}ext_tested
struct item *ext_tested(struct ctx *c) {
  struct item *i = ext_far(c);

  if (IS_ERR(i))
    return i;
  i->id = 1;
  return i;
}

// Untested, nothing is known.
// FACTS-DAG: fn{{	}}ext_untested{{	.*	}}E,c:ext_far{{	}}ext_far
struct item *ext_untested(struct ctx *c) {
  if (!c)
    return ERR_PTR(-ENODEV);
  return ext_far(c);
}

// "if (IS_ERR_OR_NULL(i)) return i;" hands the NULL on to the caller: this
// is not a test that keeps it inside.
bool IS_ERR_OR_NULL(const void *);
// FACTS-DAG: fn{{	}}ext_optional{{	.*	}}E,c:ext_far{{	}}IS_ERR_OR_NULL,ext_far
struct item *ext_optional(struct ctx *c) {
  struct item *i = ext_far(c);

  if (IS_ERR_OR_NULL(i))
    return i;
  if (i->id < 0)
    return ERR_PTR(-ENODEV);
  return i;
}

// The error does not leave the function, which tries again.
void relax(void);
// FACTS-DAG: fn{{	}}ext_retry{{	.*}}x:ext_far
struct item *ext_retry(struct ctx *c) {
  struct item *i;

again:
  i = ext_far(c);
  if (IS_ERR(i)) {
    relax();
    goto again;
  }
  return i;
}

struct ops {
  struct item *(*make)(struct ctx *c);
  struct item *cached;
};

// The result of an indirect call that is tested for NULL, and a value from
// memory that is tested with IS_ERR(): both are objects after the test.
// FACTS-DAG: fn{{	}}ext_indirect{{	.*	}}EV{{	}}-
// CONTRACTS-DAG: err_ptr{{	}}ext_indirect
struct item *ext_indirect(struct ctx *c, struct ops *o) {
  struct item *i = o->make(c);

  if (!i)
    return ERR_PTR(-ENOMEM);
  return i;
}

// FACTS-DAG: fn{{	}}ext_cached{{	.*	}}eV{{	}}IS_ERR
// CONTRACTS-DAG: err_ptr{{	}}ext_cached
struct item *ext_cached(struct ops *o) {
  struct item *i = o->cached;

  if (!IS_ERR(i))
    i->id++;
  return i;
}

void __might_sleep(const char *, int);
void take_it(void);
static void helper(void) { __might_sleep("f", 1); }

// FACTS-DAG: fn{{	}}ext_sleeps{{	.*	}}-{{	}}__might_sleep,take_it
void ext_sleeps(struct ctx *c) {
  take_it();
  helper();
}

// Only on one branch: not something the function always does.
// FACTS-DAG: fn{{	}}ext_branch{{	.*	}}-{{	}}take_it
void ext_branch(struct ctx *c) {
  take_it();
  if (c)
    helper();
}

// Told whether it may sleep.
// FACTS-NOT: fn{{	}}ext_hint
void ext_hint(struct ctx *c, int atomic) {
  if (!atomic)
    helper();
}

// CONTRACTS-DAG: err_ptr{{	}}ext_err
// CONTRACTS-DAG: err_ptr{{	}}ext_wrap
// CONTRACTS-DAG: null{{	}}ext_null
// CONTRACTS-DAG: sleeps{{	}}ext_sleeps
// CONTRACTS-NOT: {{^(err_ptr|null|sleeps)	}}ext_mixed
// CONTRACTS-NOT: {{^(err_ptr|null|sleeps)	}}ext_branch
// CONTRACTS-NOT: {{^(err_ptr|null|sleeps)	}}ext_optional
// CONTRACTS-NOT: {{^(err_ptr|null|sleeps)	}}ext_untested
// CONTRACTS-NOT: {{^(err_ptr|null)	}}ext_retry

#else

struct item *ext_err(struct ctx *c); // #ext_err
struct item *ext_null(struct ctx *c); // #ext_null
struct item *ext_wrap(struct ctx *c); // #ext_wrap
struct item *ext_mixed(struct ctx *c);

// A lookup: what it finds, or NULL.
static struct item *find_item(struct ctx *c, int id) { // #find_item
  struct item *i;

  for (i = c->first; i; i = i->next)
    if (i->id == id)
      return i;
  return NULL;
}

int use_find(struct ctx *c) {
  struct item *i = find_item(c, 1);

  if (IS_ERR(i)) // expected-warning {{find_item returns NULL on failure, which IS_ERR does not detect; test the pointer for NULL}} \
                 // expected-note@#find_item {{the return convention of 'find_item' was inferred from its definition}}
    return -ENODEV;
  return i->id;
}

// An allocation that is turned into an error pointer.
static struct item *make_item(struct ctx *c) { // #make_item
  struct item *i = kzalloc(sizeof(*i), 0);

  if (!i)
    return ERR_PTR(-ENOMEM);
  i->next = c->first;
  return i;
}

int use_make(struct ctx *c) {
  struct item *i = make_item(c);

  if (!i) // expected-warning {{make_item returns an encoded error pointer on failure, which a NULL test does not detect; use IS_ERR()}} \
          // expected-note@#make_item {{the return convention of 'make_item' was inferred from its definition}}
    return -ENOMEM;
  return 0;
}

// The error does not leave the function, which tries again: what it
// returns has passed the test, and the NULL test of the caller is odd but
// no mix of conventions.
void relax(void);

static struct item *make_item_retry(struct ctx *c) {
  struct item *i;

again:
  i = make_item(c);
  if (IS_ERR(i)) {
    relax();
    goto again;
  }
  return i;
}

int use_retry(struct ctx *c) {
  struct item *i = make_item_retry(c);

  if (!i)
    return -ENOMEM;
  return 0;
}

// An error that becomes NULL on its way out.
static struct item *make_item_or_null(struct ctx *c) { // #make_item_or_null
  struct item *i = make_item(c);

  if (IS_ERR(i))
    return NULL;
  return i;
}

int use_or_null(struct ctx *c) {
  struct item *i = make_item_or_null(c);

  if (IS_ERR(i)) // expected-warning {{make_item_or_null returns NULL on failure, which IS_ERR does not detect; test the pointer for NULL}} \
                 // expected-note@#make_item_or_null {{the return convention of 'make_item_or_null' was inferred from its definition}}
    return -ENOMEM;
  return 0;
}

// A wrapper keeps the convention of what it wraps.
static struct item *alloc_item(void) { // #alloc_item
  return kzalloc(sizeof(struct item), 0);
}

int use_alloc(void) {
  struct item *i = alloc_item();

  if (IS_ERR(i)) // expected-warning {{alloc_item returns NULL on failure, which IS_ERR does not detect; test the pointer for NULL}} \
                 // expected-note@#alloc_item {{the return convention of 'alloc_item' was inferred from its definition}}
    return -ENOMEM;
  return 0;
}

// The result of a function that nothing is known about is handed on after a
// test for NULL.  An error pointer passes that test: the function returns
// NULL as far as its body says, and its caller may know more.
struct item *pick_elsewhere(struct ctx *c);

static struct item *pick_item(struct ctx *c, struct item *have) {
  struct item *other;

  if (!have)
    return NULL;
  other = pick_elsewhere(c);
  if (!other)
    return have;
  return other;
}

int use_pick(struct ctx *c, struct item *have) {
  struct item *i = pick_item(c, have);

  if (IS_ERR(i))
    return -ENOMEM;
  return i ? 1 : 0;
}

// A stub says nothing about the function it stands in for.
static struct item *stub_item(struct ctx *c) { return ERR_PTR(-ENODEV); }

int use_stub(struct ctx *c) {
  struct item *i = stub_item(c);

  if (!i)
    return -ENODEV;
  return 0;
}

// Both conventions: every test is right.
static struct item *either(struct ctx *c) {
  if (!c)
    return NULL;
  if (c->first)
    return ERR_PTR(-ENODEV);
  return &c->slot;
}

int use_either(struct ctx *c) {
  struct item *i = either(c);

  if (!i)
    return 1;
  if (IS_ERR(i))
    return 2;
  return 0;
}

// A value from memory may be NULL: not an error pointer function.
static struct item *first_or_error(struct ctx *c) {
  if (!c)
    return ERR_PTR(-ENODEV);
  return c->first;
}

int use_first(struct ctx *c) {
  struct item *i = first_or_error(c);

  if (!i)
    return 1;
  return 0;
}

// Tested for an error: what came from memory may be an error pointer.
static struct item *cached(struct ctx *c) {
  struct item *i = c->first;

  if (!i)
    return NULL;
  if (IS_ERR(i))
    return i;
  return i;
}

int use_cached(struct ctx *c) {
  struct item *i = cached(c);

  if (IS_ERR(i))
    return 1;
  return i ? 0 : 2;
}

// A parameter that is given other values.
static struct item *replaced(struct ctx *c, struct item *i) {
  if (!i)
    i = c->first ? NULL : ERR_PTR(-ENODEV);
  return i;
}

int use_replaced(struct ctx *c, struct item *given) {
  struct item *i = replaced(c, given);

  if (IS_ERR(i))
    return 1;
  return i ? 0 : 2;
}

// Functions of another translation unit, known from the contracts file.
int use_ext(struct ctx *c) {
  struct item *i = ext_err(c);

  if (!i) // file-warning {{ext_err returns an encoded error pointer on failure, which a NULL test does not detect; use IS_ERR()}} \
          // file-note@#ext_err {{the return convention of 'ext_err' was inferred from its definition}}
    return 1;
  i = ext_null(c);
  if (IS_ERR(i)) // file-warning {{ext_null returns NULL on failure, which IS_ERR does not detect; test the pointer for NULL}} \
                 // file-note@#ext_null {{the return convention of 'ext_null' was inferred from its definition}}
    return 2;
  i = ext_wrap(c);
  if (!i) // file-warning {{ext_wrap returns an encoded error pointer on failure, which a NULL test does not detect; use IS_ERR()}} \
          // file-note@#ext_wrap {{the return convention of 'ext_wrap' was inferred from its definition}}
    return 3;
  i = ext_mixed(c);
  if (!i)
    return 4;
  return 0;
}

#endif
