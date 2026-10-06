// RUN: %clang_cc1 -triple x86_64-unknown-linux-gnu -fsyntax-only \
// RUN:   -ffreestanding -Wlinux-kernel-bitops-cast -verify=bitops %s
// RUN: %clang_cc1 -triple powerpc-unknown-linux-gnu -fsyntax-only \
// RUN:   -ffreestanding -Wlinux-kernel-bitops-cast -verify=order %s
// RUN: %clang_cc1 -triple x86_64-unknown-linux-gnu -fsyntax-only \
// RUN:   -ffreestanding -Wlinux-kernel-struct-leak -verify=leak %s
// RUN: %clang_cc1 -triple i386-unknown-linux-gnu -fsyntax-only \
// RUN:   -ffreestanding -Wlinux-kernel-struct-leak -verify=leak32 %s
// RUN: %clang_cc1 -triple x86_64-unknown-linux-gnu -fsyntax-only \
// RUN:   -ffreestanding -Wlinux-kernel-buffer-size -verify=size %s
// RUN: %clang_cc1 -triple x86_64-unknown-linux-gnu -fsyntax-only \
// RUN:   -ffreestanding -Wlinux-kernel-off-by-one -verify=bound %s
// RUN: %clang_cc1 -triple x86_64-unknown-linux-gnu -fsyntax-only \
// RUN:   -ffreestanding -Wlinux-kernel-unchecked-allocation -verify=alloc %s
// RUN: %clang_cc1 -triple x86_64-unknown-linux-gnu -fsyntax-only \
// RUN:   -ffreestanding -Wall -verify=wall %s

// wall-no-diagnostics

#define NULL ((void *)0)
#define EFAULT 14
#define ENOMEM 12
#define PAGE_SIZE 4096
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define GFP_KERNEL 0x10u
#define __GFP_NOFAIL 0x8000u

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

// Bit operations on something that is not an unsigned long.

void set_bit(long nr, volatile unsigned long *addr);
int _test_bit(long nr, const volatile unsigned long *addr);
int const_test_bit(long nr, const volatile unsigned long *addr);
#define test_bit(nr, addr)                                                     \
  (__builtin_constant_p(nr) ? const_test_bit(nr, addr) : _test_bit(nr, addr))
unsigned long find_first_bit(const unsigned long *addr, unsigned long size);
void bitmap_zero(unsigned long *dst, unsigned int nbits);

struct state {
  u16 flags;
  unsigned long bits;
  u64 wide;
};

void narrow_local(void) {
  u32 flags = 0;

  set_bit(1, (unsigned long *)&flags); // bitops-warning {{set_bit() works on unsigned long, which has 64 bits, but 'flags' has 32: the access runs past the object, and a big-endian machine numbers the bits differently}}
}

int narrow_member(struct state *s) {
  return test_bit(0, (unsigned long *)&s->flags); // bitops-warning {{test_bit() works on unsigned long, which has 64 bits, but 's->flags' has 16}} \
                                                  // order-warning {{test_bit() works on unsigned long, which has 32 bits, but 's->flags' has 16}}
}

unsigned long narrow_search(void) {
  u8 mask = 0x12;

  return find_first_bit((unsigned long *)&mask, 8); // bitops-warning {{find_first_bit() works on unsigned long, which has 64 bits, but 'mask' has 8}} \
                                                    // order-warning {{find_first_bit() works on unsigned long, which has 32 bits, but 'mask' has 8}}
}

void right_width(struct state *s) {
  unsigned long local = 0;

  set_bit(1, &local);
  set_bit(2, (unsigned long *)&local);
  set_bit(3, &s->bits);
  bitmap_zero(&s->bits, 64);
}

// A 64-bit value as two unsigned long: the words are the other way round on
// a 32-bit big-endian machine.
void two_words(struct state *s) {
  set_bit(40, (unsigned long *)&s->wide); // order-warning {{set_bit() takes 's->wide' for an array of two unsigned long, which this big-endian target stores in the other order}}
}

// Padding that goes to user space.

unsigned long copy_to_user(void *to, const void *from, unsigned long n);
void *memset(void *s, int c, unsigned long n);

struct padded {
  char kind; // leak-note 2 {{'struct padded' has padding after member 'kind'}} leak32-note 2 {{'struct padded' has padding after member 'kind'}}
  long value;
};

struct tail {
  long value;
  char kind; // leak-note {{'struct tail' has padding after member 'kind'}} leak32-note {{'struct tail' has padding after member 'kind'}}
};

struct dense {
  int a;
  int b;
};

struct wide_member {
  u32 a; // leak-note {{'struct wide_member' has padding after member 'a'}}
  u64 b;
};

void fill(struct padded *p);

static void fill_members(struct padded *p) {
  p->kind = 1;
  p->value = 2;
}

int leak(void *user) {
  struct padded p; // leak-note {{'p' is declared here without an initializer}} leak32-note {{'p' is declared here without an initializer}}

  p.kind = 1;
  p.value = 2;
  if (copy_to_user(user, &p, sizeof(p))) // leak-warning {{'p' is copied out by copy_to_user() with 7 bytes of padding that this function never initializes}} \
                                         // leak32-warning {{'p' is copied out by copy_to_user() with 3 bytes of padding that this function never initializes}}
    return -EFAULT;
  return 0;
}

int leak_at_end(void *user) {
  struct tail t; // leak-note {{'t' is declared here without an initializer}} leak32-note {{'t' is declared here without an initializer}}

  t.value = 1;
  t.kind = 2;
  return copy_to_user(user, &t, sizeof(t)) ? -EFAULT : 0; // leak-warning {{'t' is copied out by copy_to_user() with 7 bytes of padding}} \
                                                          // leak32-warning {{'t' is copied out by copy_to_user() with 3 bytes of padding}}
}

// A hole that only some ABIs have: i386 aligns 64-bit integers to 4 bytes.
int leak_by_abi(void *user) {
  struct wide_member w; // leak-note {{'w' is declared here without an initializer}}

  w.a = 1;
  w.b = 2;
  return copy_to_user(user, &w, sizeof(w)) ? -EFAULT : 0; // leak-warning {{'w' is copied out by copy_to_user() with 4 bytes of padding}}
}

int cleared(void *user) {
  struct padded p;

  memset(&p, 0, sizeof(p));
  p.kind = 1;
  return copy_to_user(user, &p, sizeof(p)) ? -EFAULT : 0;
}

int initialized(void *user) {
  struct padded p = {.kind = 1};

  return copy_to_user(user, &p, sizeof(p)) ? -EFAULT : 0;
}

int filled_elsewhere(void *user) {
  struct padded p;

  fill(&p);
  return copy_to_user(user, &p, sizeof(p)) ? -EFAULT : 0;
}

// A function that this file has the body of, and that only sets members.
int filled_by_members(void *user) {
  struct padded p; // leak-note {{'p' is declared here without an initializer}} leak32-note {{'p' is declared here without an initializer}}

  fill_members(&p);
  return copy_to_user(user, &p, sizeof(p)) ? -EFAULT : 0; // leak-warning {{'p' is copied out by copy_to_user() with 7 bytes of padding}} \
                                                          // leak32-warning {{'p' is copied out by copy_to_user() with 3 bytes of padding}}
}

static void fill_whole(struct padded *p) {
  if (p) {
    memset(p, 0, sizeof(*p));
    p->kind = 1;
  }
}

int filled_conditionally(void *user) {
  struct padded p;

  fill_whole(user ? &p : NULL);
  return user && copy_to_user(user, &p, sizeof(p)) ? -EFAULT : 0;
}

int assigned_whole(void *user, const struct padded *from) {
  struct padded p;

  p = *from;
  return copy_to_user(user, &p, sizeof(p)) ? -EFAULT : 0;
}

int no_padding(void *user) {
  struct dense d;

  d.a = 1;
  d.b = 2;
  return copy_to_user(user, &d, sizeof(d)) ? -EFAULT : 0;
}

int part_only(void *user) {
  struct padded p;

  p.kind = 1;
  return copy_to_user(user, &p, 1) ? -EFAULT : 0;
}

// A size that is larger than the buffer.

int scnprintf(char *buf, unsigned long size, const char *fmt, ...);

int show(int a, int b) {
  char buf[128];
  int len = 0;

  len += scnprintf(buf + len, PAGE_SIZE - len, "%d\n", a); // size-warning {{scnprintf() is given a size of 4096 for 'buf', which has 128 bytes}}
  len += scnprintf(buf + len, sizeof(buf) - len, "%d\n", b);
  return len;
}

struct line {
  char text[16];
};

int show_member(struct line *l) {
  return scnprintf(l->text, 32, "x"); // size-warning {{scnprintf() is given a size of 32 for 'l->text', which has 16 bytes}}
}

#define NAME_LEN (64 - sizeof(unsigned long))

int show_name(void) {
  char name[NAME_LEN];

  return scnprintf(name, NAME_LEN, "x");
}

int show_ok(char *page) {
  char buf[64];

  return scnprintf(buf, sizeof(buf), "x") + scnprintf(page, PAGE_SIZE, "y");
}

// A bounds test that lets the index be the number of elements.

static int table[16];

int lookup(unsigned int i) {
  if (i > ARRAY_SIZE(table)) // bound-note {{bounds test is here}}
    return -1;
  return table[i]; // bound-warning {{'i' can be 16 here, the number of elements of 'table': the bounds test uses '>' where '>=' is needed}}
}

int lookup_else(unsigned int i) {
  if (i <= ARRAY_SIZE(table)) // bound-note {{bounds test is here}}
    return table[i]; // bound-warning {{'i' can be 16 here}}
  return -1;
}

int lookup_ok(unsigned int i) {
  if (i >= ARRAY_SIZE(table))
    return -1;
  return table[i];
}

int lookup_changed(unsigned int i) {
  if (i > ARRAY_SIZE(table))
    return -1;
  i--;
  return table[i];
}

struct desc {
  int nr;
  long va[] __attribute__((counted_by(nr)));
};

long page_of(struct desc *d, int id) {
  return id > d->nr ? 0 : d->va[id]; // bound-warning {{'id' can be 'd->nr' here, the number of elements of 'd->va'}} \
                                     // bound-note {{bounds test is here}}
}

long page_of_ok(struct desc *d, int id) {
  return id >= d->nr ? 0 : d->va[id];
}

// The result of an allocation, dereferenced without a test.

void *kzalloc(unsigned long size, unsigned int flags);
void *kmalloc(unsigned long size, unsigned int flags);

struct thing {
  int id;
};

int unchecked(void) {
  struct thing *t = kzalloc(sizeof(*t), GFP_KERNEL);

  t->id = 1; // alloc-warning {{'t' holds the result of 'kzalloc', which is NULL when the allocation fails, and is dereferenced here without a test}}
  return 0;
}

int checked(void) {
  struct thing *t = kzalloc(sizeof(*t), GFP_KERNEL);

  if (!t)
    return -ENOMEM;
  t->id = 1;
  return 0;
}

int cannot_fail(void) {
  struct thing *t = kmalloc(sizeof(*t), GFP_KERNEL | __GFP_NOFAIL);

  t->id = 1;
  return 0;
}

int checked_copy(void) {
  struct thing *t = kzalloc(sizeof(*t), GFP_KERNEL);
  void *copy = t;

  if (!copy)
    return -ENOMEM;
  t->id = 1;
  return 0;
}

struct owner {
  struct thing *thing;
};

// The member was tested before the variable got its value.
int checked_member(struct owner *o) {
  struct thing *t;

  o->thing = kzalloc(sizeof(*t), GFP_KERNEL);
  if (o->thing == NULL)
    return -ENOMEM;
  t = o->thing;
  t->id = 1;
  return 0;
}

// Another test of the index comes before the access.

struct elems {
  unsigned int cnt;
  int elem[];
};

int second_test(struct elems *e, unsigned int i) {
  if (!e->cnt || i > e->cnt)
    return 0;
  if (i < e->cnt)
    return e->elem[i];
  return -1;
}

static unsigned char weights[16];

int tighter_test(unsigned int n) {
  if (n > ARRAY_SIZE(weights))
    return -1;
  if (n > 8)
    return -2;
  weights[n] = 0;
  return 0;
}
