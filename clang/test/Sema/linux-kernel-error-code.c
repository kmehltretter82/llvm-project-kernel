// A function that returns a count, or a negative error code if it fails: the
// result has to be looked at before it is a size or an index, and in an
// unsigned variable the error is a large number that "<= 0" does not see.
//
// With the bodies of this translation unit and the names that the compiler
// knows:
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wlinux-kernel-experimental \
// RUN:   -flinux-kernel-experimental=unsigned-error-test,error-code-as-size \
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
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wlinux-kernel-experimental \
// RUN:   -flinux-kernel-experimental=unsigned-error-test,error-code-as-size \
// RUN:   -flinux-kernel-contracts=%t/contracts -verify=expected,file %s
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wall -verify=wall %s

// wall-no-diagnostics

typedef _Bool bool;
typedef unsigned int u32;
typedef unsigned char u8;
typedef unsigned long size_t;
#define NULL ((void *)0)
#define EINVAL 22
#define ENODEV 19
#define ENOMEM 12
#define EIO 5

bool IS_ERR(const void *);
long PTR_ERR(const void *);
void *kcalloc(size_t n, size_t size, unsigned int flags);
void *kmalloc(size_t size, unsigned int flags);
void kfree(const void *);
void *__underlying_memcpy(void *, const void *, size_t);
#define memcpy(p, q, size) ({ \
  size_t __fortify_size = (size_t)(size); \
  __underlying_memcpy(p, q, __fortify_size); })
unsigned long copy_to_user(void *to, const void *from, unsigned long n);
void note(int n);

struct dev {
  int id;
  unsigned int irqs;
  int *table;
  void *regs;
};

// What other translation units define.
int count_entries(struct dev *d);
int read_reg(struct dev *d, int reg);
int number_of(struct dev *d);
int wrapped_count(struct dev *d);
unsigned int width_of(struct dev *d);
int platform_irq_count(struct dev *d);

#ifdef OTHER_UNIT
int probe_dev(struct dev *d);

int count_entries(struct dev *d) {
  if (!d->table)
    return -ENODEV;
  return d->id;
}

int read_reg(struct dev *d, int reg) {
  int ret = probe_dev(d);

  if (ret < 0)
    return ret;
  return d->table[reg];
}

int probe_dev(struct dev *d) {
  if (IS_ERR(d->regs))
    return PTR_ERR(d->regs);
  return 0;
}

// Never negative.
int number_of(struct dev *d) {
  return d->id & 0xff;
}

int wrapped_count(struct dev *d) {
  return count_entries(d);
}

unsigned int width_of(struct dev *d) {
  return d->id;
}

// FACTS-DAG: int{{.}}count_entries{{.*}}N
// FACTS-DAG: int{{.}}read_reg{{.*}}N
// FACTS-DAG: int{{.}}probe_dev{{.*}}N
// FACTS-DAG: int{{.}}wrapped_count{{.*}}N
// FACTS-NOT: int{{.}}number_of
// FACTS-NOT: int{{.}}width_of
// CONTRACTS-DAG: negative{{.}}count_entries
// CONTRACTS-DAG: negative{{.}}read_reg
// CONTRACTS-DAG: negative{{.}}wrapped_count
// CONTRACTS-NOT: negative{{.}}number_of
#else

static int local_count(struct dev *d) {
  if (!d->table)
    return -EINVAL;
  return d->id;
}

// The error is replaced before it is returned.
static int count_or_default(struct dev *d) {
  int n = local_count(d);

  if (n < 0)
    n = 4;
  return n;
}

static int count_or_zero(struct dev *d) {
  int n = local_count(d);

  n = n < 0 ? 0 : n;
  return n;
}

// The result of a function that this file has no body for.
static inline int inline_count(struct dev *d) {
  return count_entries(d);
}

// ---------------------------------------------------------------------------
// An error code in an unsigned variable.

int irqs_by_name(struct dev *d) {
  d->irqs = platform_irq_count(d); // expected-note {{the result is stored here}}
  if (d->irqs <= 0)
// expected-warning@-1 {{'d->irqs' is unsigned and holds the result of 'platform_irq_count', so this test takes the negative error code that 'platform_irq_count' can return for a large number (experimental check 'unsigned-error-test')}}
    return -ENODEV;
  return 0;
}

int irqs_local(struct dev *d) {
  u32 n;

  n = local_count(d); // expected-note {{the result is stored here}}
  note(1);
  if (n > 0)
// expected-warning@-1 {{'n' is unsigned and holds the result of 'local_count', so this test takes the negative error code that 'local_count' can return for a large number (experimental check 'unsigned-error-test')}}
    note(n);
  return 0;
}

int irqs_other_unit(struct dev *d) {
  unsigned int n = count_entries(d); // file-note {{the result is stored here}}

  if (n <= 0)
// file-warning@-1 {{'n' is unsigned and holds the result of 'count_entries', so this test takes the negative error code that 'count_entries' can return for a large number (experimental check 'unsigned-error-test')}}
    return -ENODEV;
  return 0;
}

// --- and what is no error code, or is tested as one.

int irqs_signed(struct dev *d) {
  int n = platform_irq_count(d);

  if (n <= 0)
    return -ENODEV;
  d->irqs = n;
  return 0;
}

int irqs_never_negative(struct dev *d) {
  unsigned int n = number_of(d);

  if (n <= 0)
    return -ENODEV;
  return 0;
}

int irqs_changed(struct dev *d) {
  unsigned int n = platform_irq_count(d);

  n &= 0xff;
  if (n <= 0)
    return -ENODEV;
  return 0;
}

// ---------------------------------------------------------------------------
// An error code as a size or as an index.

int *alloc_table(struct dev *d) {
  int n = local_count(d); // expected-note {{the result is stored here}}

  return kcalloc(n, sizeof(int), 0);
// expected-warning@-1 {{'n' is the size that 'kcalloc' is given here, but it holds the result of 'local_count', which can be a negative error code, and nothing in this function tests it for that (experimental check 'error-code-as-size')}}
}

int lookup(struct dev *d, const int *map) {
  int idx = platform_irq_count(d); // expected-note {{the result is stored here}}

  return map[idx];
// expected-warning@-1 {{'idx' is the index into 'map' here, but it holds the result of 'platform_irq_count', which can be a negative error code, and nothing in this function tests it for that (experimental check 'error-code-as-size')}}
}

int copy_out(struct dev *d, void *to, const void *from) {
  int len;

  len = local_count(d); // expected-note {{the result is stored here}}
  memcpy(to, from, len);
// expected-warning@-1 {{'len' is the size of a memory operation here, but it holds the result of 'local_count', which can be a negative error code, and nothing in this function tests it for that (experimental check 'error-code-as-size')}}
  return 0;
}

int to_user(struct dev *d, void *to, const void *from) {
  int len = inline_count(d); // file-note {{the result is stored here}}

  if (copy_to_user(to, from, len))
// file-warning@-1 {{'len' is the size that 'copy_to_user' is given here, but it holds the result of 'inline_count', which can be a negative error code, and nothing in this function tests it for that (experimental check 'error-code-as-size')}}
    return -EIO;
  return 0;
}

int alloc_other_unit(struct dev *d) {
  int n = read_reg(d, 0); // file-note {{the result is stored here}}

  d->table = kmalloc(n, 0);
// file-warning@-1 {{'n' is the size that 'kmalloc' is given here, but it holds the result of 'read_reg', which can be a negative error code, and nothing in this function tests it for that (experimental check 'error-code-as-size')}}
  return d->table ? 0 : -ENOMEM;
}

// A test for zero does not see the error in an unsigned variable.
int alloc_unsigned(struct dev *d) {
  unsigned int n = platform_irq_count(d); // expected-note {{the result is stored here}}

  if (!n)
    return -ENODEV;
  d->table = kcalloc(n, sizeof(int), 0);
// expected-warning@-1 {{'n' is the size that 'kcalloc' is given here, but it holds the result of 'platform_irq_count', which can be a negative error code, and nothing in this function tests it for that (experimental check 'error-code-as-size')}}
  return d->table ? 0 : -ENOMEM;
}

// --- and where the function looks at the result.

int *alloc_tested(struct dev *d) {
  int n = local_count(d);

  if (n < 0)
    return NULL;
  return kcalloc(n, sizeof(int), 0);
}

int *alloc_tested_later(struct dev *d) {
  int n = local_count(d);
  int *p = kcalloc(n, sizeof(int), 0);

  if (n <= 0)
    note(n);
  return p;
}

int alloc_unsigned_limited(struct dev *d) {
  unsigned int n = platform_irq_count(d);

  if (n > 16)
    return -EINVAL;
  d->table = kcalloc(n, sizeof(int), 0);
  return d->table ? 0 : -ENOMEM;
}

int *alloc_never_negative(struct dev *d) {
  int n = number_of(d);

  return kcalloc(n, sizeof(int), 0);
}

int *alloc_unsigned_result(struct dev *d) {
  int n = width_of(d);

  return kcalloc(n, sizeof(int), 0);
}

// Two assignments meet: nothing is known.
int *alloc_either(struct dev *d, int given) {
  int n = given;

  if (!d->id)
    n = local_count(d);
  return kcalloc(n, sizeof(int), 0);
}

// A function that is asked about the number.
bool count_ok(int n);

int *alloc_asked(struct dev *d) {
  int n = local_count(d);

  if (!count_ok(n))
    return NULL;
  return kcalloc(n, sizeof(int), 0);
}

int *alloc_default(struct dev *d) {
  int n = count_or_default(d);

  return kcalloc(n, sizeof(int), 0);
}

int *alloc_zero(struct dev *d) {
  int n = count_or_zero(d);

  return kcalloc(n, sizeof(int), 0);
}

int *alloc_clamped(struct dev *d) {
  int n = local_count(d);

  n = n < 0 ? 0 : n;
  return kcalloc(n, sizeof(int), 0);
}
#endif
