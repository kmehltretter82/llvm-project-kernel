// RUN: %clang_cc1 -fsyntax-only -ffreestanding \
// RUN:   -Wlinux-kernel-counted-by-order -verify %s
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wlinux-kernel \
// RUN:   -Wno-conditional-uninitialized -verify %s
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wall -verify=wall %s

// wall-no-diagnostics

#define NULL ((void *)0)

void *kzalloc(unsigned long, unsigned int);
void *memcpy(void *, const void *, unsigned long);

struct blob {
  int len;
  int data[] __attribute__((counted_by(len)));
};

struct plain {
  int len;
  int data[];
};

void init_blob(struct blob *b, int n);
struct blob *lookup(void);

struct blob *copied_first(const int *src, int n) {
  struct blob *b = kzalloc(sizeof(*b) + n * sizeof(int), 0); // expected-note {{the object is allocated here}}

  if (!b)
    return NULL;
  memcpy(b->data, src, n * sizeof(int)); // expected-warning {{flexible array 'data' is used before its counter 'len' is set}}
  b->len = n; // expected-note {{'len' is set here}}
  return b;
}

struct blob *filled_first(int n) {
  struct blob *b;
  int i;

  b = kzalloc(sizeof(*b) + n * sizeof(int), 0); // expected-note {{the object is allocated here}}
  if (!b)
    return NULL;
  for (i = 0; i < n; i++)
    b->data[i] = i; // expected-warning {{flexible array 'data' is used before its counter 'len' is set}}
  b->len = n; // expected-note {{'len' is set here}}
  return b;
}

int read_first(int n) {
  struct blob *b = kzalloc(sizeof(*b) + n * sizeof(int), 0); // expected-note {{the object is allocated here}}

  if (!b)
    return 0;
  return b->data[0]; // expected-warning {{flexible array 'data' is used, but its counter 'len' is not set in this function}}
}

struct blob *counter_first(const int *src, int n) {
  struct blob *b = kzalloc(sizeof(*b) + n * sizeof(int), 0);

  if (!b)
    return NULL;
  b->len = n;
  memcpy(b->data, src, n * sizeof(int));
  return b;
}

// The callee may set the counter.
struct blob *through_helper(int n) {
  struct blob *b = kzalloc(sizeof(*b) + n * sizeof(int), 0);

  if (!b)
    return NULL;
  init_blob(b, n);
  b->data[0] = 1;
  return b;
}

// The counter grows with the array.
struct blob *appended(int n) {
  struct blob *b = kzalloc(sizeof(*b) + n * sizeof(int), 0);
  int i;

  if (!b)
    return NULL;
  for (i = 0; i < n; i++) {
    b->data[b->len] = i;
    b->len++;
  }
  return b;
}

// Not allocated here: the counter was set by whoever made the object.
int not_fresh(void) {
  struct blob *b = lookup();

  return b ? b->data[0] : 0;
}

// No counter to wait for.
struct plain *uncounted(int n) {
  struct plain *p = kzalloc(sizeof(*p) + n * sizeof(int), 0);

  if (!p)
    return NULL;
  p->data[0] = 1;
  p->len = n;
  return p;
}

// kzalloc_flex() and its relatives store the counter themselves, through a
// pointer of their own.
#define alloc_flex(type, member, count)                                        \
  ({                                                                           \
    type *__obj = kzalloc(sizeof(type) + (count) * sizeof(int), 0);            \
    if (__obj)                                                                 \
      *__builtin_counted_by_ref(__obj->member) = (count);                      \
    __obj;                                                                     \
  })

struct blob *with_flex_helper(int n) {
  struct blob *b = alloc_flex(struct blob, data, n);

  if (!b)
    return NULL;
  b->data[0] = 1;
  return b;
}
